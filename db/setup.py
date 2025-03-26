# db/setup.py
import sqlite3

def init_db():
    conn = sqlite3.connect("db/netwatch.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            device_name TEXT,
            ip TEXT,
            domain TEXT,
            app TEXT,
            port INTEGER
        )
    """)
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
