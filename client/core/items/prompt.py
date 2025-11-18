from .schemas import SCHEMAS, FIELD_MAXLEN
from ...utils.logger import CTX
from ...utils import logger as log
from ...utils.display import prompt_field

def prompt_fields_for_type(item_type):
    schema = SCHEMAS[item_type]
    fields = {}

    current_user = ""  # si tu veux le username ici, adapte
    logger = log.get_logger(CTX.ITEM_CREATE, current_user)

    for field in schema["required"]:
        max_len = FIELD_MAXLEN[field]
        label = "Item name" if field.value == "name" else field.value
        fields[field.value] = prompt_field(label, max_len, allow_empty=False, logger=logger)

    for field in schema["recommended"]:
        max_len = FIELD_MAXLEN[field]
        label = "Item name" if field.value == "name" else field.value
        fields[field.value] = prompt_field(label, max_len, allow_empty=True, logger=logger)

    return fields
