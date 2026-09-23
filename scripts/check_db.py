"""Quick script to check alive nodes in main DB."""
import sqlite3
import os

db_path = 'K:/work/AmuleD_v2/db/amuled.db'
print(f'DB exists: {os.path.exists(db_path)}')
if os.path.exists(db_path):
    print(f'DB size: {os.path.getsize(db_path)}')
    # Check if it's actually a SQLite DB
    with open(db_path, 'rb') as f:
        header = f.read(16)
        print(f'Header: {header}')
        if header != b'SQLite format 3\x00':
            print('Not a SQLite database! Trying DuckDB...')
            import duckdb
            con = duckdb.connect(db_path)
            result = con.execute("SELECT COUNT(*) FROM kad_nodes WHERE hellos > 0").fetchall()
            print(f'Alive nodes in main DB (DuckDB): {result[0][0]}')
            con.close()
        else:
            con = sqlite3.connect(db_path)
            cur = con.cursor()
            cur.execute("SELECT COUNT(*) FROM kad_nodes WHERE hellos > 0")
            print(f'Alive nodes in main DB: {cur.fetchone()[0]}')
            con.close()
