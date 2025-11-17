from enum import Enum

class Type(str, Enum):
    LOGIN = "Login"
    ALIAS = "Alias"
    CARD = "Card"
    NOTE = "Note"
    IDENTITY = "Identity"
    OTHER = "Other"

class Field(str, Enum):
    TITLE = "Title"
    USERNAME = "Username"
    PASSWORD = "Password"
    URL = "URL"
    BODY = "Body"
    EMAIL = "Email"
    NOTES = "Notes"
    CARD_NUMBER = "Card number"
    EXPIRY = "Expiry"
    HOLDER = "Holder"
    CVV = "CVV"
    FIRSTNAME = "Firstname"
    LASTNAME = "Lastname"
    PHONE = "Phone"

FIELD_MAXLEN = {
    Field.TITLE: 30,
    Field.USERNAME: 50,
    Field.PASSWORD: 50,
    Field.URL: 200,
    Field.BODY: 5000,
    Field.EMAIL: 100,
    Field.NOTES: 1000,
    Field.CARD_NUMBER: 20,
    Field.EXPIRY: 10,
    Field.HOLDER: 50,
    Field.CVV: 4,
    Field.FIRSTNAME: 50,
    Field.LASTNAME: 50,
    Field.PHONE: 20,
}

SCHEMAS = {
    Type.LOGIN: {
        "required": [Field.TITLE],
        "recommended": [Field.USERNAME, Field.PASSWORD, Field.URL],
    },
    Type.NOTE: {
        "required": [Field.TITLE],
        "recommended": [Field.BODY],
    },
    Type.ALIAS: {
        "required": [Field.TITLE],
        "recommended": [Field.EMAIL, Field.NOTES],
    },
    Type.CARD: {
        "required": [Field.TITLE, Field.CARD_NUMBER],
        "recommended": [Field.EXPIRY, Field.HOLDER, Field.CVV],
    },
    Type.IDENTITY: {
        "required": [Field.TITLE],
        "recommended": [Field.FIRSTNAME, Field.LASTNAME, Field.EMAIL, Field.PHONE],
    },
    Type.OTHER: {
        "required": [Field.TITLE],
        "recommended": [],
    },
}