import hashlib
from pathlib import Path
from fastapi import UploadFile
from app.core.config import settings

APK_MAGIC = b"PK\x03\x04"

def validate_filename(filename: str | None):
    if not filename or Path(filename).suffix.lower() != settings.allowed_extension:
        raise ValueError("UNSUPPORTED_FILE")

def validate_bytes(data: bytes):
    if len(data) > settings.max_upload_bytes:
        raise ValueError("FILE_TOO_LARGE")
    if not data.startswith(APK_MAGIC):
        raise ValueError("INVALID_APK")

def save_upload(upload: UploadFile, scan_id: str) -> tuple[str, str]:
    validate_filename(upload.filename)
    data = upload.file.read(settings.max_upload_bytes + 1)
    validate_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    directory = Path(settings.upload_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{scan_id}.apk"
    path.write_bytes(data)
    return str(path), digest
