"""Curated security patches for controlled demonstration of Fix Verification Engine."""

# 1. Valid, effective fix: Replaces raw string interpolation with parameterized SQL bindings
VALID_FIX_PATCH = """--- a/auth_gateway/dao/user_query.py
+++ b/auth_gateway/dao/user_query.py
@@ -1,6 +1,6 @@
 def get_user_by_tenant(cursor, tenant_id: str, email: str):
     \"\"\"Retrieve user record by tenant and email.
-    VULNERABILITY: Raw f-string SQL query formatting without parameterized binding (CWE-89).
+    FIXED: Properly parameterized SQL query with argument tuple binding.
     \"\"\"
-    cursor.execute(f"SELECT * FROM users WHERE tenant_id = '{tenant_id}' AND email = '{email}'")
+    cursor.execute("SELECT * FROM users WHERE tenant_id = %s AND email = %s", (tenant_id, email))
     return cursor.fetchone()
"""

# 2. Ineffective fix: Modifies comments/variable but STILL uses raw string formatting
INEFFECTIVE_FIX_PATCH = """--- a/auth_gateway/dao/user_query.py
+++ b/auth_gateway/dao/user_query.py
@@ -1,6 +1,7 @@
 def get_user_by_tenant(cursor, tenant_id: str, email: str):
     \"\"\"Retrieve user record by tenant and email.
     VULNERABILITY: Raw f-string SQL query formatting without parameterized binding (CWE-89).
     \"\"\"
-    cursor.execute(f"SELECT * FROM users WHERE tenant_id = '{tenant_id}' AND email = '{email}'")
+    clean_tid = str(tenant_id)
+    cursor.execute(f"SELECT * FROM users WHERE tenant_id = '{clean_tid}' AND email = '{email}'")
     return cursor.fetchone()
"""

# 3. Regression-inducing fix: Fixes SQLi but introduces hardcoded secret / command execution
REGRESSION_FIX_PATCH = """--- a/auth_gateway/dao/user_query.py
+++ b/auth_gateway/dao/user_query.py
@@ -1,6 +1,8 @@
+import os
+API_KEY = "AKIAIOSFODNN7EXAMPLE"
 def get_user_by_tenant(cursor, tenant_id: str, email: str):
     \"\"\"Retrieve user record by tenant and email.
-    VULNERABILITY: Raw f-string SQL query formatting without parameterized binding (CWE-89).
+    FIXED: Parameterized query.
     \"\"\"
-    cursor.execute(f"SELECT * FROM users WHERE tenant_id = '{tenant_id}' AND email = '{email}'")
+    cursor.execute("SELECT * FROM users WHERE tenant_id = %s AND email = %s", (tenant_id, email))
     return cursor.fetchone()
"""

# 4. Malicious patch with directory traversal attempt
PATH_TRAVERSAL_PATCH = """--- a/../../../../etc/shadow
+++ b/../../../../etc/shadow
@@ -1,1 +1,1 @@
-root:*
+root:hacked
"""
