# AmuleD v0.6.0 — Audit Checklist

Автор: Soror L.'.L.'.
Обновлён: 2026-09-27

Каждая строка: утверждение → команда воспроизведения → ожидаемый результат →
категория (`live` = живой пир/сеть, `мои тесты`
= offline suite этого репозитария).

Команды выполняются из корня `K:\work\AmuleD_v2` в PowerShell:

```powershell
$env:PYTHONPATH='K:\work\AmuleD_v2\src'; $env:AMULED_ROOT='K:\work\AmuleD_v2'
$py = '.\.venv\Scripts\python.exe'
```

Ядро (`AmuleD_Run.ps1 serve`) на время offline-проверок ОСТАНОВЛЕНО
(`amuled daemon stop`), иначе все DB-команды и pytest падают на rw-локе.

## 1. Версия и релизная гигиена

| Утверждение | Команда | Ожидаемый результат | Категория |
|---|---|---|---|
| Публичная версия 0.6.0 | `& $py -c "import sys; sys.path.insert(0,'src'); from amuled_v2 import __version_string__; print(__version_string__)"` | `AmuleD v0.6.0` | мои тесты |
| `--help` отвечает и печатает баннер | `& $py -m amuled_v2 --help` | справка CLI, код 0 | мои тесты |
| Версия в тестах синхронизирована | `& $py -m pytest -q tests/test_skeleton.py` | passed | мои тесты |
| pyproject-версия совпадает | grep `version = "0.6.0"` `pyproject.toml` | ровно одно совпадение | мои тесты |

## 2. Единое ядро (стадия U, фазы 1–3)

| Утверждение | Команда | Ожидаемый результат | Категория |
|---|---|---|---|
| Ядро стартует и пишет kernel_status.json | `.\AmuleD_Run.ps1 serve` (затем `& $py -m amuled_v2 daemon status --json`) | `running: true`, serve_port, control_port, spider | мои тесты (live) |
| Повторный serve отклоняется | второй `.\AmuleD_Run.ps1 serve` | refusal, код ≠ 0 | мои тесты (live) |
| Остановка через IPC | `& $py -m amuled_v2 daemon stop --json` | `stopping: true`, файл статуса удалён | мои тесты (live) |
| Read-only CLI работает ПОД живым ядром | при живом ядре: `& $py -m amuled_v2 search results list --json`, `sources list --json`, `download list --json`, `servers failures --json`, `ipfilter status --json`, `share list --json`, `credits list --json` | все `status: ok` через IPC, без DuckDB-ошибок блокировки | мои тесты (live) |
| IPC-обработчики ядра зелёные offline | `& $py -m pytest -q tests/test_kernel.py` | 7 passed | мои тесты |
| download.add через ядро | при живом ядре: `& $py -m amuled_v2 download add "ed2k://\|file\|t\|1\|<32hex>\|/" --json` | `status: ok`, `queue: queued` | мои тесты (live) |
| Контент-гейт не обходится через ядро | `download add` с маркерным именем (см. tests/test_kernel.py) | `status: error`, файл НЕ в очереди | мои тесты |
| Part-файлы download.add идут в temp, БД изолируется в тестах | `& $py -m pytest -q tests/test_kernel.py::test_kernel_ipc_phase3_handlers` | passed, в `temp\` нет мусора | мои тесты |
| Spider-режим помечен устаревшим | `.\AmuleD_Run.ps1 spider` | `[RUNNER] [WARN] DEPRECATED ... use serve` перед стартом | мои тесты (live) |
| Меню работает под живым ядром | `.\AmuleD_Run.ps1` → пункты KAD status, Share list, Downloads list, Servers failures | рендер без ошибок блокировки БД | мои тесты (live) |

## 3. KAD publish / search / sources (стадия P)

| Утверждение | Команда | Ожидаемый результат | Категория |
|---|---|---|---|
| Publish keywords | `& $py -m amuled_v2 publish keywords --limit 1 --json` | accepts > 0 | мои тесты (live) |
| Publish sources с фактическим портом | `& $py -m amuled_v2 publish sources --limit 1 --json` | accepts > 0 | мои тесты (live) |
| KAD-поиск находит наш файл из сети | `& $py -m amuled_v2 search kad <полное имя файла> --json` | hash/size совпадают | мои тесты (live) |
| Wire-регрессия count-байта тегов | `& $py -m pytest -q tests/test_publish.py` | passed | мои тесты |

## 4. Upload / listener / credits (стадии S, C)

| Утверждение | Команда | Ожидаемый результат | Категория |
|---|---|---|---|
| Loopback self-test раздачи | `& $py -m pytest -q tests/test_serve_selftest.py tests/test_kernel.py -k vertical` | passed, MD4 сверен | мои тесты |
| Credits начисляются при отдаче | после loopback-раздачи: `& $py -m amuled_v2 credits list --json` | uploaded ≥ размер файла | мои тесты (live) |
| SecureIdent: RSA-384 sign/verify + SUI wire (взаимная верификация) | `& $py -m pytest -q tests/test_credits.py tests/test_sui_wire.py` | passed | мои тесты |
| Полный offline suite | `& $py -m pytest -q tests --ignore=tests/test_live_ed2k.py` | все passed/known-skipped, 0 failed | мои тесты |

## 5. Клиентская обфускация

| Утверждение | Команда | Ожидаемый результат | Категория |
|---|---|---|---|
| Клиентский obf-handshake к живому пиру | историческая live-приёмка сессии 7 (MorphXT HANDSHAKE OK ×4) | подтверждено ранее | мои тесты (live, разовая) |
| Серверный accept обфускации (входящий) | `& $py -m pytest -q tests/test_listener.py -k "obfuscated or dh"` | passed (BASIC+DH accept в listener) | мои тесты |

## 6. Отложенное (стадия X и паритет раздачи)

| Утверждение | Команда | Ожидаемый результат | Категория |
|---|---|---|---|
| MISCOPTIONS-биты HELLO соответствуют возможностям | сверка cap-констант codec.py с GetMyConnectOptions (eMuleAI) | сверено (сессии 10/14: SX/AICH/SUI включены по факту responder'ов) | мои тесты |
| GeoIP подключён | `& $py -m amuled_v2 geoip lookup 8.8.8.8 --json` | страна определена (maxminddb + legacy fallback) | мои тесты |
| UPnP/NAT-PMP | `& $py -m amuled_v2 nat status --json` | map/unmap в ядре (`nat.enabled`) | мои тесты |
| QUEUERANK-периодика, slot rotation, credits→priority | `& $py -m pytest -q tests/test_listener.py tests/test_kernel.py` | passed (queue_rank_period, expired_slots, credit_bonus) | мои тесты |
| known.met import/export CLI | `& $py -m amuled_v2 import known-met --json` | импорт (парсер сверен: 904/904) | мои тесты |

## 7. Гигиена репозитария

| Утверждение | Команда | Ожидаемый результат | Категория |
|---|---|---|---|
| Нет мусора вне задокументированных путей | `git status --short` | только ожидаемые изменения | мои тесты |
| Temp-политика соблюдена | grep логов/тестов на `%TEMP%`, `AppData` | попаданий нет; всё в `tmp\` / `.cache\tmp\` | мои тесты |
| Приватные файлы не коммитятся | проверка staged перед коммитом | нет `docs\*.md`, `config\`, `db\`, `logs\`, `tmp\`, `assets\v1\shared_files.json` | мои тесты |
