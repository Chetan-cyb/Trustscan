import re
from pathlib import Path
from androguard.core.apk import APK
from .permissions import PERMISSION_INFO

class APKAnalyzer:
    version = "apk-static-1.0"

    def analyze(self, path: str) -> dict:
        apk = APK(path)
        permissions = sorted(apk.get_permissions() or [])
        app_name = apk.get_app_name()
        activities = sorted(apk.get_activities() or [])
        services = sorted(apk.get_services() or [])
        receivers = sorted(apk.get_receivers() or [])
        providers = sorted(apk.get_providers() or [])
        exported = []
        for component in activities + services + receivers + providers:
            try:
                if apk.get_element("application", "android:exported", False):
                    exported.append(component)
            except Exception:
                pass
        urls = []
        try:
            raw = Path(path).read_bytes()
            for m in re.findall(rb'https?://[^\x00\s"<>]{4,300}', raw):
                try:
                    u = m.decode("utf-8", "ignore")
                    if u not in urls: urls.append(u)
                except Exception: pass
                if len(urls) >= 100: break
        except Exception:
            pass
        perm_view = []
        for p in permissions:
            name, explanation, risk = PERMISSION_INFO.get(p, (p.split('.')[-1].replace('_',' ').title(), f"This app requests the {p} permission.", "unknown"))
            perm_view.append({"permission": p, "name": name, "explanation": explanation, "risk": risk})
        return {
            "analyzer_version": self.version,
            "application_name": app_name,
            "package_name": apk.get_package(),
            "version_name": apk.get_androidversion_name(),
            "version_code": apk.get_androidversion_code(),
            "min_sdk": apk.get_min_sdk_version(),
            "target_sdk": apk.get_target_sdk_version(),
            "permissions": perm_view,
            "activities": activities,
            "services": services,
            "receivers": receivers,
            "providers": providers,
            "exported_components": exported,
            "embedded_urls": urls,
            "native_libraries": sorted([str(x) for x in (apk.get_files() or []) if str(x).startswith("lib/") and str(x).endswith(".so")]),
        }
