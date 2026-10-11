def get_user_by_tenant(cursor, tenant_id: str, email: str):
    """Retrieve user record by tenant and email.
    VULNERABILITY: Raw f-string SQL query formatting without parameterized binding (CWE-89).
    """
    cursor.execute(f"SELECT * FROM users WHERE tenant_id = '{tenant_id}' AND email = '{email}'")
    return cursor.fetchone()
