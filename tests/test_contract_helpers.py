import main

def base_state():
    return {
        "runId": "run-test-0001", "publicMarker": "public-safe-marker",
        "_trace_id": "1" * 32, "_agent_span_id": "2" * 16, "_spans": [],
        "_pending": {}, "_action_spans": {}, "actionLog": [], "_tracestate": None
    }

def test_retry_keeps_one_logical_tool_span_and_unique_client_spans():
    state = base_state()
    first = main.create_dispatch(state, "query_metrics", {"service": "checkout"},
                                 "diagnostic", ["ev_0001"])
    first_pending = state["_pending"][first["actionId"]]
    retry = main.create_dispatch(state, "query_metrics", {"service": "checkout"},
                                 "diagnostic", ["ev_0001"], attempt=2,
                                 existing_action=first["actionId"], existing_call=first["callId"])
    assert retry["actionId"] == first["actionId"]
    assert retry["callId"] == first["callId"]
    assert retry["attempt"] == 2
    assert len([s for s in state["_spans"] if s["name"].startswith("execute_tool ")]) == 1
    assert len([s for s in state["_spans"] if s["kind"] == 3]) == 2
    assert len({s["spanId"] for s in state["_spans"]}) == len(state["_spans"])
    assert retry["traceparent"].split("-")[2] == state["_pending"][retry["actionId"]]["clientSpanId"]
    assert first_pending["logicalSpanId"] == state["_pending"][retry["actionId"]]["logicalSpanId"]

def test_schema_validation_rejects_wrong_arguments(monkeypatch):
    req = {
        "incident": {"allowedRootCauses": ["bad config"], "transcript": "[ev_0001] one\n[ev_0002] two"},
        "toolCatalog": [
            {"name":"query_metrics", "inputSchema":{"type":"object","required":["service"],"properties":{"service":{"type":"string"}}}},
            {"name":"page_owner", "inputSchema":{"type":"object","required":["team"],"properties":{"team":{"type":"string"}}}}
        ],
        "policy": {"maximumDiagnostics": 1, "effectTools":["page_owner"], "approvalRequiredFor":[]}
    }
    monkeypatch.setattr(main, "OPENROUTER_API_KEY", "test")
    class FakeResp:
        def raise_for_status(self): pass
        def json(self):
            return {"choices":[{"message":{"content":'{"rootCause":"bad config","evidence":["ev_0001","ev_0002"],"diagnostics":[{"toolName":"query_metrics","arguments":{},"evidence":["ev_0001"]}],"effect":{"toolName":"page_owner","arguments":{"team":"ops"}}}'}}]}
    class FakeClient:
        def __init__(self, *a, **kw): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def post(self, *a, **kw): return FakeResp()
    monkeypatch.setattr(main.httpx, "Client", FakeClient)
    try:
        main.safe_model_plan(req)
        assert False, "schema-invalid plan should be rejected"
    except Exception as e:
        assert getattr(e, "status_code", None) == 422

def test_otlp_public_state_does_not_expose_internal_plan():
    state = base_state()
    state["_plan"] = {"secret": "internal"}
    state["status"] = "waiting"
    state["actionLog"] = []
    state["receiptLog"] = []
    state["_spans"] = []
    result = main.public_state(state)
    assert "_plan" not in result
    assert "otlp" in result
