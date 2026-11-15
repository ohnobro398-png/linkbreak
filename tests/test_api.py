"""API tests via FastAPI TestClient (no real network)."""

import pytest
from fastapi.testclient import TestClient

import app.main as main_mod


@pytest.fixture()
def client(tmp_path):
    main_mod.DB_PATH = str(tmp_path / "test.db")
    main_mod._hits.clear()
    with TestClient(main_mod.app) as test_client:
        yield test_client


def test_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_index_serves_ui(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "LINKBREAK" in response.text
    assert "Honest limitations" in response.text


def test_static_css_served(client):
    response = client.get("/static/styles.css")
    assert response.status_code == 200
    assert "safety-domain" in response.text


def test_resolve_not_a_url(client):
    response = client.post("/api/resolve", json={"url": "not-a-url"})
    assert response.status_code == 400


def test_resolve_empty_url(client):
    response = client.post("/api/resolve", json={"url": ""})
    assert response.status_code == 422


def test_resolve_non_http_scheme_blocked(client):
    response = client.post("/api/resolve", json={"url": "ftp://example.com/file"})
    assert response.status_code == 200
    body = response.json()
    assert body["resolution_status"] == "Blocked"
    assert body["original_url"] == "ftp://example.com/file"


def test_resolve_localhost_blocked(client):
    response = client.post("/api/resolve", json={"url": "http://localhost/admin"})
    assert response.status_code == 200
    assert response.json()["resolution_status"] == "Blocked"


def test_resolve_unsupported_provider(client):
    response = client.post(
        "/api/resolve", json={"url": "http://" + "linkvertise.com/abc"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["resolution_status"] == "Unsupported"
    assert body["detected_provider"] == "linkvertise.com"


def test_resolve_response_shape(client):
    response = client.post("/api/resolve", json={"url": "http://127.0.0.1/x"})
    body = response.json()
    for key in (
        "original_url", "detected_provider", "final_url", "redirect_chain",
        "http_status", "resolution_status", "error_message", "elapsed_ms",
        "canonical_url", "canonical_source", "original_domain",
        "final_domain", "domain_changed", "brand_mismatch", "safety_notes",
    ):
        assert key in body, f"missing key {key}"


def test_batch_limit_enforced(client):
    response = client.post(
        "/api/batch-resolve",
        json={"urls": [f"http://example.com/{i}" for i in range(21)]},
    )
    assert response.status_code == 422


def test_batch_resolve_blocked_hosts(client):
    response = client.post(
        "/api/batch-resolve",
        json={"urls": ["http://localhost/a", "http://10.0.0.1/b"]},
    )
    assert response.status_code == 200
    bodies = response.json()
    assert len(bodies) == 2
    assert all(b["resolution_status"] == "Blocked" for b in bodies)


def test_history_roundtrip(client):
    client.post("/api/resolve", json={"url": "http://localhost/a"})
    history = client.get("/api/history").json()
    assert len(history) == 1
    assert history[0]["original_url"] == "http://localhost/a"
    assert history[0]["resolution_status"] == "Blocked"

    deleted = client.delete("/api/history").json()
    assert deleted["deleted"] == 1
    assert client.get("/api/history").json() == []
