from enum import Enum

class Type(str, Enum):
    LOGIN = "login"
    ALIAS = "alias"
    CARD = "card"
    NOTE = "note"
    IDENTITY = "identity"
    OTHER = "other"

class Field(str, Enum):
    TITLE = "title"
    USERNAME = "username"
    PASSWORD = "password"
    URL = "url"
    BODY = "body"
    EMAIL = "email"
    NOTES = "notes"
    CARD_NUMBER = "card_number"
    EXPIRY = "expiry"
    HOLDER = "holder"
    CVV = "cvv"
    FIRSTNAME = "firstname"
    LASTNAME = "lastname"
    PHONE = "phone"

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