import sqlite3
from modules import storage

def main():
    db_path = storage.DB_PATH
    print("DB:", db_path)
    conn = sqlite3.connect(str(db_path))
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = [r[0] for r in cur.fetchall()]
    print("tables:", tables)
    conn.close()

if __name__ == '__main__':
    main()
