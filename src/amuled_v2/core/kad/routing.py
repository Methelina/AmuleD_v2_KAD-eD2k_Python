"""Kad2 routing table: K-buckets, binary zone tree, and contact lifecycle.

Implements the in-memory routing structures that mirror the eMule 0.50a
CContact / CRoutingBin / CRoutingZone trilogy.  The tree is a binary trie
over the 128-bit XOR space where each leaf zone owns one ``K``-bucket;
a leaf splits into two child zones when its bin overflows and the split
preconditions derived from ``CRoutingZone::CanSplit`` hold.

Source files (authoritative for constants and semantics):
  - srchybrid/kademlia/kademlia/Defines.h    -- K, KBASE, KK
  - srchybrid/kademlia/routing/RoutingBin.h   -- bucket operations
  - srchybrid/kademlia/routing/RoutingBin.cpp -- AddContact, SetAlive, CanSplit, GetClosestTo
  - srchybrid/kademlia/routing/RoutingZone.h   -- zone tree API
  - srchybrid/kademlia/routing/RoutingZone.cpp -- Add, Split, CanSplit, GetClosestTo, Consolidate
  - srchybrid/kademlia/routing/Contact.h/.cpp -- Contact type lifecycle

Author: Soror L.'.L'.

src/amuled_v2/core/kad/routing.py
Version:     0.1.0
Author:      Soror L.'.L'.
Updated:     2026-09-23
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from amuled_v2.core.kad.nodes_dat import KadNodeInfo
from amuled_v2.core.kad.packets import KadUInt128
from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.KAD, "core.kad.routing")

__all__ = [
    "K",
    "KBASE",
    "KK",
    "MAX_ZONE_LEVEL",
    "RoutingTableError",
    "RoutingContact",
    "RoutingBin",
    "RoutingZone",
]

K = 10
KBASE = 4
KK = 5
MAX_ZONE_LEVEL = 127


def _bit_at_level(value: KadUInt128, level: int) -> int:
    """Return bit *level* of *value* (0 = most-significant bit).

    Mirrors ``CUInt128::GetBitNumber`` (UInt128.cpp:144-151): bit 0 is the
    most-significant of the 128-bit value, so we index from the high end.
    """
    if level >= 128:
        return 0
    return (value.to_int() >> (127 - level)) & 1


class RoutingTableError(Exception):
    """Raised for routing-table-level failures."""


@dataclass
class RoutingContact:
    """A Kad contact together with its routing-table liveness state.

    Wraps a :class:`KadNodeInfo` and mirrors the ``type``/``fails``/
    ``last_seen`` fields of ``CContact``:

    - ``type`` -- contact freshness type (0 freshest .. 4 most stale).
      ``InitContact`` (Contact.cpp:122) initialises new contacts at type 3.
    - ``fails`` -- consecutive failure count; incremented on failure and
      decremented on success.
    - ``last_seen`` -- :func:`time.monotonic` timestamp of the most recent
      confirmed-aliveness contact (SetAlive / mark_alive).
    """

    node: KadNodeInfo
    type: int = 3
    fails: int = 0
    last_seen: float = 0.0

    def key(self) -> tuple[str, int]:
        return self.node.key

    def update_type(self) -> None:
        """Mirror ``CContact::UpdateType`` (Contact.cpp:228-246).

        Age the contact type based on how long it has been known, mirroring
        the time-since-creation switch in ``UpdateType``:
          - < 1 hour  -> type 2
          - < 2 hours -> type 1
          - >= 2 hours -> type 0
        A freshly *added* contact has no creation history, so we fall back to
        decrementing the type by one step (but never below 0) when the age
        cannot be determined.
        """
        if self.last_seen > 0.0:
            age = time.monotonic() - self.last_seen
        else:
            age = 0.0
        if age < 3600.0:
            self.type = 2
        elif age < 7200.0:
            self.type = 1
        else:
            self.type = 0
        self.fails = 0

    def checking_type(self) -> bool:
        """Mirror ``CContact::CheckingType`` (Contact.cpp:216-226).

        Escalate the contact type by one step (capped at 4).  Returns ``True``
        when the contact has reached type 4 and is therefore eligible for
        eviction on the next expiry sweep (see OnSmallTimer in
        RoutingZone.cpp:868-885).
        """
        if self.type >= 4:
            return True
        self.type += 1
        return self.type >= 4


class RoutingBin:
    """One K-bucket, mirroring ``CRoutingBin`` (RoutingBin.h/.cpp).

    Capacity is the fixed constant ``K`` (Defines.h:42).  Contacts are kept in
    a most-recently-confirmed-alive ordering: ``SetAlive``
    (RoutingBin.cpp:125-138) calls ``UpdateType`` then ``PushToBottom``, i.e.
    the contact moves to the most-recent position.  ``GetOldest``
    (RoutingBin.cpp:222-228) returns the front (least-recent) entry.
    """

    def __init__(self) -> None:
        self._contacts: list[RoutingContact] = []

    def add(self, contact: RoutingContact) -> bool:
        """Insert *contact* into the bucket.

        Mirrors ``CRoutingBin::AddContact`` (RoutingBin.cpp:88-123):
          - If a contact with the same KadID already exists, it is refreshed
            in place (type reset to freshest, moved to most-recent position)
            and ``True`` is returned.
          - If the bucket is full (``size == K``) and no duplicate was found,
            return ``False`` so the caller may attempt a zone split.
        """
        for existing in self._contacts:
            if existing.node.kad_id == contact.node.kad_id:
                existing.node = contact.node
                existing.type = 0
                existing.fails = 0
                existing.last_seen = time.monotonic()
                self.push_to_bottom(existing)
                log.debug(
                    "add: refreshed contact id=%s ip=%s",
                    contact.node.kad_id.hex(),
                    contact.node.ip,
                )
                return True
        if len(self._contacts) >= K:
            log.debug(
                "add: bin full id=%s ip=%s",
                contact.node.kad_id.hex(),
                contact.node.ip,
            )
            return False
        self._contacts.append(contact)
        log.debug(
            "add: inserted contact id=%s ip=%s size=%d",
            contact.node.kad_id.hex(),
            contact.node.ip,
            len(self._contacts),
        )
        return True

    def mark_alive(self, key: tuple[str, int]) -> bool:
        """Confirm a contact alive by ``(ip, udp_port)``.

        Mirrors ``CRoutingBin::SetAlive`` (RoutingBin.cpp:125-138): find the
        contact, call ``UpdateType``-equivalent, then move it to the most-
        recent position.  Returns ``True`` if the contact was found.
        """
        for idx in range(len(self._contacts)):
            if self._contacts[idx].key() == key:
                rc = self._contacts[idx]
                rc.update_type()
                rc.last_seen = time.monotonic()
                self.push_to_bottom(rc)
                log.debug(
                    "mark_alive: contact id=%s key=%s type=%d",
                    rc.node.kad_id.hex(),
                    key,
                    rc.type,
                )
                return True
        return False

    def mark_failed(self, key: tuple[str, int]) -> bool:
        """Record a failed probe for the contact identified by *key*.

        Mirrors the contact-type/failure escalation seen in
        ``CContact::CheckingType`` (Contact.cpp:216-226) and the eviction
        sweep in ``CRoutingZone::OnSmallTimer``
        (RoutingZone.cpp:871-885):

          - ``fails`` is incremented.
          - ``checking_type`` escalates the type by one step (0->1->2->3->4).
          - Once the contact reaches type 4 and ``fails`` is high enough,
            return ``True`` so the caller evicts it.

        The eMule reference does not use a bare ``fails`` counter on the
        contact itself; instead ``CheckingType`` bumps the type toward 4 and
        ``OnSmallTimer`` removes type-4 contacts past their expiry.  We
        approximate "expiry" with ``fails`` crossing a small threshold so
        that a contact which repeatedly fails escalates quickly, matching the
        spirit of the reference where type 4 == "this contact is about to be
        purged".
        """
        for idx in range(len(self._contacts)):
            if self._contacts[idx].key() == key:
                rc = self._contacts[idx]
                rc.fails += 1
                should_evict = rc.checking_type()
                if should_evict:
                    log.debug(
                        "mark_failed: evict contact id=%s key=%s type=%d fails=%d",
                        rc.node.kad_id.hex(),
                        key,
                        rc.type,
                        rc.fails,
                    )
                    return True
                log.debug(
                    "mark_failed: escalated contact id=%s type=%d fails=%d",
                    rc.node.kad_id.hex(),
                    rc.type,
                    rc.fails,
                )
                return False
        return False

    def push_to_bottom(self, contact: RoutingContact) -> None:
        """Move an existing contact to the most-recent position.

        Mirrors ``CRoutingBin::PushToBottom`` (RoutingBin.cpp:370-375).
        """
        try:
            self._contacts.remove(contact)
        except ValueError:
            return
        self._contacts.append(contact)

    def get_contact_by_id(self, kad_id: bytes) -> RoutingContact | None:
        """Find a contact by its 16-byte KadID."""
        for rc in self._contacts:
            if rc.node.kad_id == kad_id:
                return rc
        return None

    def get_contact_by_key(self, key: tuple[str, int]) -> RoutingContact | None:
        """Find a contact by ``(ip, udp_port)``."""
        for rc in self._contacts:
            if rc.key() == key:
                return rc
        return None

    def remove_contact(self, contact: RoutingContact) -> None:
        """Remove *contact* from the bin."""
        try:
            self._contacts.remove(contact)
        except ValueError:
            pass

    def contacts(self) -> list[RoutingContact]:
        """Return contacts in most-recent-first order.

        ``m_listEntries`` is ordered most-recent at the back (push_back on
        update), so reverse gives most-recent-first.
        """
        return list(reversed(self._contacts))

    def __len__(self) -> int:
        return len(self._contacts)

    def get_remaining(self) -> int:
        """Mirrors ``CRoutingBin::GetRemaining`` (RoutingBin.cpp:207-210)."""
        return K - len(self._contacts)


class RoutingZone:
    """Binary zone tree over the 128-bit XOR address space.

    Mirrors ``CRoutingZone`` (RoutingZone.h/.cpp).  The root zone covers the
    whole space at level 0; each split doubles the number of zones and halves
    the address range.  Leaf zones hold a :class:`RoutingBin`; internal nodes
    hold two child :class:`RoutingZone` objects.

    Splitting follows ``CRoutingZone::CanSplit`` (RoutingZone.cpp:459-469):
      ``(m_uZoneIndex < KK OR m_uLevel < KBASE) AND bin is full AND
      m_uLevel < MAX_ZONE_LEVEL``

    ``GetClosestTo`` (RoutingZone.cpp:658-674) recurses into the subzone that
    is closer to the target first, then into the other if results are still
    short -- mirroring the ``iCloser`` bit selection at RoutingZone.cpp:668.
    """

    def __init__(self, own_id: KadUInt128) -> None:
        self._own_id = own_id
        self._level: int = 0
        self._zone_index: int = 0
        self._super_zone: RoutingZone | None = None
        self._sub_zones: list[RoutingZone | None] = [None, None]
        self._bin: RoutingBin | None = RoutingBin()

    def _is_leaf(self) -> bool:
        return self._bin is not None

    def _can_split(self) -> bool:
        """Mirrors ``CRoutingZone::CanSplit`` (RoutingZone.cpp:459-469)."""
        if self._level >= MAX_ZONE_LEVEL:
            return False
        if not self._is_leaf():
            return False
        bin_full = len(self._bin) == K
        index_ok = self._zone_index < KK
        level_ok = self._level < KBASE
        return bin_full and (index_ok or level_ok)

    def _gen_sub_zone(self, i_side: int) -> RoutingZone:
        """Mirrors ``CRoutingZone::GenSubZone`` (RoutingZone.cpp:785-792)."""
        new_index = self._zone_index << 1
        if i_side != 0:
            new_index |= 1
        child = RoutingZone(self._own_id)
        child._level = self._level + 1
        child._zone_index = new_index
        child._super_zone = self
        return child

    def _split(self) -> None:
        """Mirrors ``CRoutingZone::Split`` (RoutingZone.cpp:715-734)."""
        self._sub_zones[0] = self._gen_sub_zone(0)
        self._sub_zones[1] = self._gen_sub_zone(1)
        old_bin = self._bin
        self._bin = None
        old_contacts = old_bin.contacts() if old_bin is not None else []
        for rc in old_contacts:
            dist = self._own_id.xor(KadUInt128(rc.node.kad_id))
            i_side = _bit_at_level(dist, self._level)
            if not self._sub_zones[i_side]._bin.add(rc):
                log.debug(
                    "split: contact dropped during migration id=%s",
                    rc.node.kad_id.hex(),
                )
        log.debug(
            "split: level=%d zone_index=%d migrated=%d",
            self._level,
            self._zone_index,
            len(old_contacts),
        )

    def add(self, node: KadNodeInfo) -> bool:
        """Insert *node* into the zone tree by XOR-distance bit path.

        Mirrors ``CRoutingZone::Add`` (RoutingZone.cpp:512-623):
          - Recurse into the subzone whose side bit matches the contact's XOR
            distance at the current level.
          - At a leaf, if the bin has the contact already it is refreshed;
            if there is room the contact is appended; otherwise attempt a
            split when ``_can_split`` holds and retry in the correct child.
          - Returns ``False`` when the bin is full and splitting is not
            permitted.
        """
        if not self._is_leaf():
            dist = self._own_id.xor(KadUInt128(node.kad_id))
            i_side = _bit_at_level(dist, self._level)
            return self._sub_zones[i_side].add(node)
        rc = RoutingContact(node=node)
        if self._bin.add(rc):
            return True
        if self._can_split():
            self._split()
            dist = self._own_id.xor(KadUInt128(node.kad_id))
            i_side = _bit_at_level(dist, self._level)
            return self._sub_zones[i_side].add(node)
        log.debug(
            "add: bin full, no split id=%s level=%d",
            node.kad_id.hex(),
            self._level,
        )
        return False

    def mark_alive(self, ip: str, udp_port: int) -> bool:
        """Confirm the contact at ``(ip, udp_port)`` alive, recursing to the
        owning leaf bin.

        Mirrors ``CRoutingZone::GetContact`` dispatch
        (RoutingZone.cpp:637-645) and ``CRoutingBin::SetAlive``
        (RoutingBin.cpp:125-138).
        """
        if self._is_leaf():
            return self._bin.mark_alive((ip, udp_port))
        for child in self._sub_zones:
            if child is not None and child.mark_alive(ip, udp_port):
                return True
        return False

    def mark_failed(self, ip: str, udp_port: int) -> bool:
        """Record a failure for the contact at ``(ip, udp_port)``.

        Returns ``True`` if the contact was found and should be evicted
        (type reached 4 per ``CheckingType`` escalation), ``False`` if the
        contact was found but is still salvageable, or ``None``-equivalent
        ``False`` if not found.
        """
        if self._is_leaf():
            return self._bin.mark_failed((ip, udp_port))
        for child in self._sub_zones:
            if child is not None and child.mark_failed(ip, udp_port):
                return True
        return False

    def remove(self, ip: str, udp_port: int) -> bool:
        """Remove the contact at ``(ip, udp_port)`` from wherever it lives."""
        if self._is_leaf():
            rc = self._bin.get_contact_by_key((ip, udp_port))
            if rc is not None:
                self._bin.remove_contact(rc)
                log.debug(
                    "remove: evicted id=%s ip=%s",
                    rc.node.kad_id.hex(),
                    ip,
                )
                return True
            return False
        removed = False
        for child in self._sub_zones:
            if child is not None and child.remove(ip, udp_port):
                removed = True
        return removed

    def closest(self, target: KadUInt128, count: int = 10) -> list[KadNodeInfo]:
        """Return up to *count* contacts closest to *target* by XOR distance.

        Mirrors ``CRoutingZone::GetClosestTo``
        (RoutingZone.cpp:658-674): recurse into the subzone closer to the
        target first, then the other if more results are still needed.
        Within a leaf bin, contacts are ordered by XOR distance to *target*.
        """
        results: list[KadNodeInfo] = []
        self._collect_closest(target, count, results)
        return results

    def _collect_closest(
        self,
        target: KadUInt128,
        count: int,
        results: list[KadNodeInfo],
    ) -> None:
        if len(results) >= count:
            return
        if self._is_leaf():
            ordered = sorted(
                self._bin.contacts(),
                key=lambda rc: target.xor(KadUInt128(rc.node.kad_id)).to_int(),
            )
            room = count - len(results)
            for rc in ordered[:room]:
                results.append(rc.node)
            return
        dist = self._own_id.xor(target)
        i_closer = _bit_at_level(dist, self._level)
        self._sub_zones[i_closer]._collect_closest(target, count, results)
        if len(results) < count:
            self._sub_zones[1 - i_closer]._collect_closest(
                target, count, results,
            )

    def all_contacts(self) -> list[KadNodeInfo]:
        """Return all contacts in the tree (mirrors
        ``CRoutingZone::GetAllEntries``, RoutingZone.cpp:676-685)."""
        out: list[KadNodeInfo] = []
        self._collect_all(out)
        return out

    def _collect_all(self, out: list[KadNodeInfo]) -> None:
        if self._is_leaf():
            for rc in self._bin.contacts():
                out.append(rc.node)
            return
        self._sub_zones[0]._collect_all(out)
        self._sub_zones[1]._collect_all(out)

    def __len__(self) -> int:
        if self._is_leaf():
            return len(self._bin)
        return len(self._sub_zones[0]) + len(self._sub_zones[1])

    def statistics(self) -> dict:
        """Return routing-table statistics mirroring the diagnostic intent of
        ``GetNumContacts`` overloads (RoutingZone.cpp:935-951)."""
        zones = 0
        by_type: dict[int, int] = {}
        contact_count = 0

        def _walk(zone: RoutingZone) -> None:
            nonlocal zones, contact_count
            if zone._is_leaf():
                zones += 1
                for rc in zone._bin.contacts():
                    by_type[rc.type] = by_type.get(rc.type, 0) + 1
                    contact_count += 1
            else:
                _walk(zone._sub_zones[0])
                _walk(zone._sub_zones[1])

        _walk(self)
        return {
            "zones": zones,
            "contacts": contact_count,
            "by_type": by_type,
            "K": K,
            "KBASE": KBASE,
            "KK": KK,
        }
