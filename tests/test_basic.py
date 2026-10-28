import json
from fastapi.testclient import TestClient
import main

client = TestClient(main.app)

def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["ok"] is True

def test_unknown_run_404():
    r = client.get("/v2/incidents/not-a-real-run")
    assert r.status_code == 404

def test_bad_profile_rejected_before_planner(monkeypatch):
    payload = {
        "profile": "wrong", "runId": "test-run-0001", "agentName": "incident-response",
        "publicMarker": "marker", "sensitive": {"accessToken":"dont-leak"},
        "incident": {"incidentId":"i", "title":"t", "service":"s", "severity":"SEV-1",
                     "transcript":"[ev_0001] signal one\n[ev_0002] signal two",
                     "allowedRootCauses":["cause"]},
        "toolCatalog": [{"name":"query_metrics","description":"query","inputSchema":{"type":"object"}}],
        "policy": {"maximumDiagnostics":1,"effectTools":["page_owner"],"approvalRequiredFor":[]}
    }
    monkeypatch.setattr(main, "safe_model_plan", lambda req: (_ for _ in ()).throw(AssertionError("must not call planner")))
    r = client.post("/v2/incidents", json=payload)
    assert r.status_code == 400
    assert "dont-leak" not in r.text

def test_canonical_hash_stable():
    assert main.digest({"b":2,"a":1}) == main.digest({"a":1,"b":2})
