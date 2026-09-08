from app.risk_engine.engine import assess

def test_camera_permission_is_not_malware():
    r = assess({"permissions":[{"permission":"android.permission.CAMERA","risk":"medium"}],"embedded_urls":[]})
    assert r["score"] < 100
    assert "malware" not in r["level"].lower()

def test_sms_pair_adds_evidence():
    r = assess({"permissions":[{"permission":"android.permission.READ_SMS","risk":"high"},{"permission":"android.permission.SEND_SMS","risk":"high"}],"embedded_urls":[]})
    assert any("SMS" in x["title"] for x in r["evidence"])
