"""Fixed demo cast shared by `seed-demo` and the walkthrough script (spec 0011).

These credentials are intentionally public and protect only a local demo
instance. `seed-demo` refuses to run unless ENV is dev, and the walkthrough
refuses non localhost targets without --allow-remote.
"""

from dataclasses import dataclass

from app.models.enums import ClassificationLevel, UserRole


@dataclass(frozen=True)
class DemoUser:
    username: str
    email: str
    display_name: str
    password: str
    role: UserRole
    clearance: ClassificationLevel
    totp_secret: str


DEMO_ADMIN = DemoUser(
    username="demo-admin",
    email="demo-admin@example.invalid",
    display_name="Demo Admin",
    password="DemoAdmin!Passw0rd2026",
    role=UserRole.ADMIN,
    clearance=ClassificationLevel.TOP_SECRET,
    totp_secret="HGX2B3UCVEEIXLSPGU67PJYGTNTOI7W5",
)

DEMO_AUDITOR = DemoUser(
    username="demo-auditor",
    email="demo-auditor@example.invalid",
    display_name="Demo Auditor",
    password="DemoAudit!Passw0rd2026",
    role=UserRole.AUDITOR,
    clearance=ClassificationLevel.UNCLASSIFIED,
    totp_secret="DHEAXCEYQVYTMD2TMH6VFNUUBVA7KM6G",
)

DEMO_OFFICER_LOW = DemoUser(
    username="demo-officer-low",
    email="demo-officer-low@example.invalid",
    display_name="Demo Officer Low",
    password="DemoLow!Passw0rd2026",
    role=UserRole.USER,
    clearance=ClassificationLevel.CONFIDENTIAL,
    totp_secret="EMOLQZ42KF4Q4ESKNA2PHLGUZA6SGZEF",
)

DEMO_OFFICER_MID = DemoUser(
    username="demo-officer-mid",
    email="demo-officer-mid@example.invalid",
    display_name="Demo Officer Mid",
    password="DemoMid!Passw0rd2026",
    role=UserRole.USER,
    clearance=ClassificationLevel.SECRET,
    totp_secret="7FYUBYS5CRWCX4726EOHRJGC7HVFQMYK",
)

DEMO_OFFICER_HIGH = DemoUser(
    username="demo-officer-high",
    email="demo-officer-high@example.invalid",
    display_name="Demo Officer High",
    password="DemoHigh!Passw0rd2026",
    role=UserRole.USER,
    clearance=ClassificationLevel.TOP_SECRET,
    totp_secret="HBBDP2RXNGWFC6ZVV22RJEFBCR7CJRMD",
)

DEMO_USERS: tuple[DemoUser, ...] = (
    DEMO_ADMIN,
    DEMO_AUDITOR,
    DEMO_OFFICER_LOW,
    DEMO_OFFICER_MID,
    DEMO_OFFICER_HIGH,
)

BY_USERNAME: dict[str, DemoUser] = {user.username: user for user in DEMO_USERS}
