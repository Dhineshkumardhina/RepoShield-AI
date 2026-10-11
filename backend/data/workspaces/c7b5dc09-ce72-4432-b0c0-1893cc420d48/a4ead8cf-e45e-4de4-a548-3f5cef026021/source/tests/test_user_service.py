import sqlite3
from src.user_service import query_user

def test_normal_user_lookup(tmp_path):
    db = str(tmp_path / 'test.db')
    conn = sqlite3.connect(db)
    conn.execute('CREATE TABLE users (id INT, username TEXT)')
    conn.execute("INSERT INTO users VALUES (1, 'alice')")
    conn.commit()
    conn.close()
    res = query_user(db, 'alice')
    assert res == (1, 'alice')
