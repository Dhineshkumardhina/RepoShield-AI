"""Health-check and service liveness tests."""
from fastapi.testclient import TestClient


def test_api_v1_health_returns_ok(client: TestClient):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["ok", "degraded"]
    assert data["service"] == "RepoShield AI"
    assert data["version"] == "0.1.0"
    assert "timestamp" in data
    assert data["database"]["status"] == "connected"
    assert data["database"]["dialect"] == "sqlite"
    assert data["uptime_seconds"] >= 0


def test_root_and_top_level_health_endpoints(client: TestClient):
    # Discovery endpoint
    res_root = client.get("/")
    assert res_root.status_code == 200
    assert res_root.json()["organization"] == "Xerova Digital Solutions"

    # Convenience health endpoint
    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "ok"

    # Legacy /api/health endpoint
    res_api_health = client.get("/api/health")
    assert res_api_health.status_code == 200
    assert res_api_health.json()["status"] == "ok"


def test_readiness_and_liveness_probes(client: TestClient):
    ready_res = client.get("/api/v1/ready")
    assert ready_res.status_code == 200
    assert ready_res.json() == {"status": "ready"}

    live_res = client.get("/api/v1/live")
    assert live_res.status_code == 200
    assert live_res.json() == {"status": "alive"}
