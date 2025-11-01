import sqlite3, os
from typing import List, Tuple, Optional

DB_PATH = "vault.db"

def connect():
    return sqlite3.connect(DB_PATH)

def init_db():
    con = connect()
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS meta (
            k TEXT PRIMARY KEY,
            v BLOB NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site TEXT NOT NULL,
            username TEXT NOT NULL,
            password BLOB NOT NULL
        )
    """)
    con.commit()
    con.close()

def get_meta(key: str) -> Optional[bytes]:
    con = connect(); cur = con.cursor()
    cur.execute("SELECT v FROM meta WHERE k=?", (key,))
    row = cur.fetchone()
    con.close()
    return row[0] if row else None

def set_meta(key: str, value: bytes):
    con = connect(); cur = con.cursor()
    cur.execute("INSERT OR REPLACE INTO meta(k, v) VALUES(?,?)", (key, value))
    con.commit(); con.close()

def add_entry(site: str, username: str, enc_password: bytes):
    con = connect(); cur = con.cursor()
    cur.execute("INSERT INTO entries(site, username, password) VALUES(?,?,?)",
                (site, username, enc_password))
    con.commit(); con.close()

def list_entries() -> List[Tuple[int, str, str, bytes]]:
    con = connect(); cur = con.cursor()
    cur.execute("SELECT id, site, username, password FROM entries ORDER BY id DESC")
    rows = cur.fetchall()
    con.close()
    return rows

def delete_entry(row_id: int):
    con = connect(); cur = con.cursor()
    cur.execute("DELETE FROM entries WHERE id=?", (row_id,))
    con.commit(); con.close()
