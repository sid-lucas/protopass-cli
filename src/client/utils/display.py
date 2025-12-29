import textwrap
from datetime import datetime
from typing import Iterable, Mapping, Sequence, Any
from . import logger as log
from .logger import CTX, notify_user


def _shorten(text, width):
    if not text:
        return ""
    return textwrap.shorten(text, width=width, placeholder="…")

def format_timestamp(value: str | None) -> str:
    if not value:
        return "-"
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return value
    return dt.strftime("%d %b %Y %H:%M")


def render_table(rows: Iterable[Mapping[str, str]], columns: Sequence[tuple[str, str, int]]) -> str:
    """
    Rend un tableau ASCII.

    rows: itérable de dicts (indexés par les clés fournies)
    columns: liste de colonnes (clé dans row, intitulé, largeur minimale)
    """
    materialized_rows = list(rows)
    if not materialized_rows:
        return ""

    widths = []
    for key, header, min_width in columns:
        content_width = max(len(str(row.get(key, ""))) for row in materialized_rows)
        widths.append(max(len(header), min_width, content_width))

    header_line = "  ".join(header.ljust(width) for (_, header, _), width in zip(columns, widths))
    separator = "-" * len(header_line)

    lines = [header_line, separator]
    for row in materialized_rows:
        parts = []
        for (key, _, _), width in zip(columns, widths):
            value = str(row.get(key, ""))
            parts.append(_shorten(value, width).ljust(width))
        lines.append("  ".join(parts))

    lines.append("")
    lines.append(f"Total: {len(materialized_rows)}")

    return "\n" + "\n".join(lines)



def render_item_details(data: Mapping[str, Any]) -> str:
    """
    Rendu lisible d'un item (une ligne par champ, wrapping propre).
    """

    timestamp_keys = {"created_at", "updated_at"}
    ordered_rows: list[tuple[str, str]] = []
    meta_rows: list[tuple[str, str]] = []

    def normalize(key: str, value: Any) -> tuple[str, str]:
        label = key.replace("_", " ").lower()
        if key in timestamp_keys and isinstance(value, str):
            display = format_timestamp(value)
        elif value is None or value == "":
            display = "-"
        else:
            display = str(value)
        return label, display

    for k, v in data.items():
        label, display = normalize(k, v)
        (meta_rows if k in timestamp_keys else ordered_rows).append((label, display))

    all_rows = ordered_rows + meta_rows
    if not all_rows:
        return ""

    label_width = max(len(label) for label, _ in all_rows)
    value_width = max(30, 100 - label_width - 3)

    def render_rows(rows: list[tuple[str, str]]) -> list[str]:
        lines = []
        for label, value in rows:
            wrapped = textwrap.wrap(value, width=value_width) or [""]
            first_line = f"{label.ljust(label_width)} : {wrapped[0]}"
            lines.append(first_line.rstrip())
            for extra in wrapped[1:]:
                lines.append(" " * (label_width + 3) + extra)
        return lines

    lines = render_rows(ordered_rows)
    if meta_rows:
        if lines:
            sep_len = max(10, label_width + value_width + 3)
            lines.append("-" * (sep_len))
        lines.extend(render_rows(meta_rows))

    return "\n".join(lines)

def verify_prompt(value, label, max_len, allow_empty, logger):
    normalized = ""
    if value is None:
        normalized = ""
    elif isinstance(value, str):
        normalized = value.strip()
    else:
        normalized = str(value).strip()

    if not normalized and allow_empty:
        return None

    if not normalized:
        logger.warning(f"Empty value provided for '{label}'")
        notify_user(f"{label} cannot be empty.")
        return False

    if len(normalized) > max_len:
        logger.warning(f"Value for '{label}' exceeds {max_len} characters")
        notify_user(f"{label} can't exceed {max_len} chars.")
        return False
    
    return True


def prompt_field(label, max_len, allow_empty, logger):
    suffix = " (optional)" if allow_empty else ""
    prompt = f"{label}{suffix}: "

    while True:
        value = input(prompt).strip()

        valid = verify_prompt(value, label, max_len, allow_empty, logger)

        if valid is None:
            return None

        if valid is False:
             continue
        
        return value
