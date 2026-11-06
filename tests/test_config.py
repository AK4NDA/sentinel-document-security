import base64

import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_master_key_must_be_base64() -> None:
    with pytest.raises(ValidationError):
        Settings(master_key="not-base64")


def test_master_key_must_decode_to_32_bytes() -> None:
    with pytest.raises(ValidationError):
        Settings(master_key=base64.b64encode(b"too-short").decode("ascii"))


def test_master_key_accepts_base64_32_bytes() -> None:
    encoded = base64.b64encode(b"x" * 32).decode("ascii")

    settings = Settings(master_key=encoded)

    assert settings.master_key.get_secret_value() == encoded


def test_cors_origins_are_parsed_as_a_list() -> None:
    settings = Settings(
        master_key=base64.b64encode(b"x" * 32).decode("ascii"),
        cors_origins="http://localhost:5173, http://127.0.0.1:5173",
    )

    assert settings.cors_origin_list == [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]
