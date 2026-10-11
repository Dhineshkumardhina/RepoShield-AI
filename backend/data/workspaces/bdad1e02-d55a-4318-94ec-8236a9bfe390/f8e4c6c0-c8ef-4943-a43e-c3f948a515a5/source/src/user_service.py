import sqlite3

def query_user(db_path, username):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # VULNERABLE: Direct f-string interpolation
    query = f"SELECT id, username FROM users WHERE username = '{username}'"
    cursor.execute(query)
    row = cursor.fetchone()
    conn.close()
    return row
