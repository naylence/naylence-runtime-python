from datetime import datetime, timezone
from enum import Enum


class AnsiColor(str, Enum):
    """ANSI color codes for terminal output."""

    RESET = "\033[0m"
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    GRAY = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"


def format_timestamp() -> str:
    """Get current timestamp in ISO format with microseconds and Z suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def color(text: str, color: AnsiColor) -> str:
    """Colorize text with the given ANSI color code.

    Args:
        text: The text to colorize.
        color: The ANSI color code to apply.

    Returns:
        The colorized text.
    """
    return f"{color.value}{text}{AnsiColor.RESET.value}"
