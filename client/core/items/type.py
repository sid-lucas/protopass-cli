from enum import Enum

class ItemType(str, Enum):
    LOGIN = "login"
    ALIAS = "alias"
    CARD = "card"
    NOTE = "note"
    IDENTITY = "identity"
    OTHER = "other"