DANGEROUS = {"high": 8, "medium": 4, "low": 1, "unknown": 0}

def assess(result: dict) -> dict:
    points = 0
    evidence = []
    for p in result.get("permissions", []):
        if p["risk"] in DANGEROUS:
            points += DANGEROUS[p["risk"]]
    perms = {p["permission"] for p in result.get("permissions", [])}
    if "android.permission.READ_SMS" in perms and "android.permission.SEND_SMS" in perms:
        points += 6
        evidence.append({"type":"suspicious","title":"SMS read/send combination","detail":"The app requests both SMS reading and SMS sending permissions. This combination can be legitimate for some apps, but deserves attention when it is unrelated to the app's purpose.","severity":"high"})
    if "android.permission.REQUEST_INSTALL_PACKAGES" in perms:
        evidence.append({"type":"suspicious","title":"Can request installation of other apps","detail":"The manifest requests the ability to request installation of other packages. Static analysis cannot tell whether it actually installs anything.","severity":"high"})
    if result.get("embedded_urls"):
        evidence.append({"type":"suspicious","title":"Embedded web addresses found","detail":f"Static inspection found {len(result['embedded_urls'])} web address(es). Their purpose or safety was not determined by this MVP.","severity":"low"})
    score = max(0, min(100, 100 - points * 3))
    level = "LOW RISK" if score >= 80 else "MODERATE RISK" if score >= 60 else "HIGH RISK"
    return {"score": score, "level": level, "basis":"Explainable assessment based only on static evidence observed by the analyzer; not a malware verdict.", "evidence": evidence}
