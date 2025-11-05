import textwrap
from datetime import datetime
from typing import Iterable, Mapping, Sequence


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
    lines.append(f"Total: {len(materialized_rows)} vault(s)")

    return "\n" + "\n".join(lines)