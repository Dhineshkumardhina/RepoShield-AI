from unittest.mock import MagicMock
from auth_gateway.dao.user_query import get_user_by_tenant


def test_normal_user_query():
    """Unit test: normal user query operation."""
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = {"id": 418, "email": "engineer@xerova.com"}
    res = get_user_by_tenant(mock_cursor, "tenant-42", "engineer@xerova.com")
    assert res["id"] == 418
    assert mock_cursor.execute.called


def test_security_sql_injection_protection():
    """Security regression test: verify that malicious user payload is bound via parameters and not raw string."""
    mock_cursor = MagicMock()
    payload = "tenant' OR '1'='1"
    get_user_by_tenant(mock_cursor, payload, "test@xerova.com")

    # Invariant: cursor.execute must have been called with parameterized arguments
    args = mock_cursor.execute.call_args[0]
    raw_query = args[0]
    
    # Payload must NOT be formatted directly into the query string
    assert payload not in raw_query, "Security failure: SQL injection payload formatted directly into SQL query string!"
    # Parameters must be supplied as a tuple or list
    assert len(args) > 1 and isinstance(args[1], (tuple, list)), "Security failure: query does not use parameterized arguments tuple!"
