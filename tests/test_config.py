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


def test_alert_hourly_cap_defaults_to_20() -> None:
    settings = Settings(master_key=base64.b64encode(b"x" * 32).decode("ascii"))

    assert settings.alert_hourly_cap == 20


def test_alert_hourly_cap_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        Settings(
            master_key=base64.b64encode(b"x" * 32).decode("ascii"),
            alert_hourly_cap=0,
        )


def test_cors_origins_are_parsed_as_a_list() -> None:
    settings = Settings(
        master_key=base64.b64encode(b"x" * 32).decode("ascii"),
        cors_origins="http://localhost:5173, http://127.0.0.1:5173",
    )

    assert settings.cors_origin_list == [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]


def test_maintenance_settings_defaults() -> None:
    settings = Settings(master_key=base64.b64encode(b"x" * 32).decode("ascii"))

    assert settings.maintenance_interval_seconds == 3600
    assert settings.maintenance_share_alert_retention_days == 90
    assert settings.maintenance_blob_min_age_seconds == 3600


def test_maintenance_interval_allows_zero_but_not_negative() -> None:
    encoded = base64.b64encode(b"x" * 32).decode("ascii")

    assert Settings(master_key=encoded, maintenance_interval_seconds=0)
    with pytest.raises(ValidationError):
        Settings(master_key=encoded, maintenance_interval_seconds=-1)


@pytest.mark.parametrize(
    "field",
    ["maintenance_share_alert_retention_days", "maintenance_blob_min_age_seconds"],
)
def test_maintenance_retention_settings_must_be_positive(field: str) -> None:
    encoded = base64.b64encode(b"x" * 32).decode("ascii")

    with pytest.raises(ValidationError):
        Settings(master_key=encoded, **{field: 0})


def test_export_max_rows_defaults_to_50000() -> None:
    settings = Settings(master_key=base64.b64encode(b"x" * 32).decode("ascii"))

    assert settings.export_max_rows == 50000


def test_export_max_rows_must_be_positive() -> None:
    encoded = base64.b64encode(b"x" * 32).decode("ascii")

    with pytest.raises(ValidationError):
        Settings(master_key=encoded, export_max_rows=0)


def test_maintenance_settings_read_env_vars(monkeypatch) -> None:
    monkeypatch.setenv("MAINTENANCE_INTERVAL_SECONDS", "5")
    monkeypatch.setenv("MAINTENANCE_SHARE_ALERT_RETENTION_DAYS", "30")
    monkeypatch.setenv("MAINTENANCE_BLOB_MIN_AGE_SECONDS", "600")

    settings = Settings(master_key=base64.b64encode(b"x" * 32).decode("ascii"))

    assert settings.maintenance_interval_seconds == 5
    assert settings.maintenance_share_alert_retention_days == 30
    assert settings.maintenance_blob_min_age_seconds == 600
