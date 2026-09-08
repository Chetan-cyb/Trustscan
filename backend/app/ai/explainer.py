def explain(analysis: dict, risk: dict) -> dict:
    # Deterministic fallback is intentional. An LLM must only receive structured verified facts.
    perms = analysis.get("permissions", [])
    if risk["score"] >= 80:
        summary = "No obvious high-risk static indicators were identified in this analysis. This does not prove the app is safe."
    elif risk["score"] >= 60:
        summary = "Some permissions or static indicators deserve attention. The analysis does not prove malicious behavior."
    else:
        summary = "Several high-impact permissions or indicators were found. Be cautious before installing this app."
    return {"summary": summary, "ai_used": False, "explanation_source": "deterministic_verified_findings"}
