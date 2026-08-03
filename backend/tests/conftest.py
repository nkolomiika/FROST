import sys
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))
import os
import datetime
import sys
import types


REQUIRED_TEST_ENV = {
    "DATABASE_URL": "postgresql+asyncpg://user:password@localhost:5432/pcf_test",
    "JWT_SECRET_KEY": "test_secret_key_that_has_minimum_length_32_chars",
    "MINIO_ENDPOINT": "localhost:9000",
    "MINIO_ACCESS_KEY": "minioadmin",
    "MINIO_SECRET_KEY": "minioadmin",
    "MINIO_BUCKET_NAME": "pcf-files-test",
    "CSRF_ALLOWED_ORIGINS": "http://localhost:3000,http://frontend.local",
}


for key, value in REQUIRED_TEST_ENV.items():
    os.environ.setdefault(key, value)

if not hasattr(datetime, "UTC"):
    datetime.UTC = datetime.timezone.utc  # type: ignore[attr-defined]

if "magic" not in sys.modules:
    magic_stub = types.ModuleType("magic")
    magic_stub.from_buffer = lambda _content, mime=True: "application/octet-stream"
    sys.modules["magic"] = magic_stub
