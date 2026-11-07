import base64
import os
from pathlib import Path

os.environ.setdefault("ENV", "dev")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("MASTER_KEY", base64.b64encode(b"\x00" * 32).decode("ascii"))
os.environ.setdefault("UPLOAD_DIR", str(Path("data/test-uploads")))
os.environ.setdefault("LOG_LEVEL", "INFO")
os.environ.setdefault("RATE_LIMIT_ENABLED", "false")
