import enum


class UserRole(enum.StrEnum):
    ADMIN = "admin"
    USER = "user"
    AUDITOR = "auditor"


class ClassificationLevel(enum.IntEnum):
    UNCLASSIFIED = 1
    RESTRICTED = 2
    CONFIDENTIAL = 3
    SECRET = 4
    TOP_SECRET = 5
