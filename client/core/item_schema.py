from enum import Enum

class Type(str, Enum):
    LOGIN = "login"
    ALIAS = "alias"
    CARD = "card"
    NOTE = "note"
    IDENTITY = "identity"
    OTHER = "other"

class Field(str, Enum):
    NAME = "name"
    EMAIL = "email"
    PASSWORD = "password"
    TOTP_SECRET = "totp"
    URL = "url"
    BODY = "body"
    NOTES = "notes"
    CARDNUMBER = "cardnumber"
    EXPIRY = "expiry"
    HOLDER = "holder"
    CVV = "cvv"
    FIRSTNAME = "firstname"
    LASTNAME = "lastname"
    PHONE = "phone"

FIELD_MAXLEN = {
    Field.NAME: 30,
    Field.EMAIL: 100,
    Field.PASSWORD: 50,
    Field.TOTP_SECRET: 100,
    Field.URL: 200,
    Field.NOTES: 1000,
    Field.CARDNUMBER: 20,
    Field.EXPIRY: 10,
    Field.HOLDER: 50,
    Field.CVV: 4,
    Field.FIRSTNAME: 50,
    Field.LASTNAME: 50,
    Field.PHONE: 20,
}

SCHEMAS = {
    Type.LOGIN: {
        "required": [Field.NAME],
        "recommended": [Field.EMAIL, Field.PASSWORD, Field.URL],
    },
    Type.NOTE: {
        "required": [Field.NAME],
        "recommended": [Field.NOTES],
    },
    Type.ALIAS: {
        "required": [Field.NAME],
        "recommended": [Field.EMAIL, Field.NOTES],
    },
    Type.CARD: {
        "required": [Field.NAME, Field.CARDNUMBER],
        "recommended": [Field.EXPIRY, Field.HOLDER, Field.CVV],
    },
    Type.IDENTITY: {
        "required": [Field.NAME],
        "recommended": [Field.FIRSTNAME, Field.LASTNAME, Field.EMAIL, Field.PHONE],
    },
    Type.OTHER: {
        "required": [Field.NAME],
        "recommended": [],
    },
}
