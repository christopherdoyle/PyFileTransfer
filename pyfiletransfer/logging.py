from __future__ import annotations
import logging
import sys
from enum import Enum
from typing import List


class AnsiEscapeCode:

    ESCAPE: str = "\x1b"
    value: int

    def __and__(self, other: AnsiEscapeCode) -> CompoundAnsiEscapeCode:
        if not isinstance(other, AnsiEscapeCode):
            raise TypeError
        return CompoundAnsiEscapeCode([self, other])

    def __str__(self) -> str:
        return f"{self.ESCAPE}[{self.value}m"


class CompoundAnsiEscapeCode(AnsiEscapeCode):
    def __init__(self, codes: List[AnsiEscapeCode]) -> None:
        self.codes = codes

    def __and__(self, other: AnsiEscapeCode) -> CompoundAnsiEscapeCode:
        if isinstance(other, CompoundAnsiEscapeCode):
            return CompoundAnsiEscapeCode(self.codes + other.codes)
        elif isinstance(other, AnsiEscapeCode):
            return CompoundAnsiEscapeCode(self.codes + [other])
        else:
            raise TypeError

    def __str__(self) -> str:
        value = ";".join(f"{x.value}" for x in self.codes)
        return f"{self.ESCAPE}[{value}m"


class Special(AnsiEscapeCode, Enum):
    RESET = 0


class Color(AnsiEscapeCode, Enum):
    BLACK = 30
    RED = 31
    GREEN = 32
    YELLOW = 33
    BLUE = 34
    MAGENTA = 35
    CYAN = 36
    WHITE = 37
    BRIGHT_BLACK = 90
    BRIGHT_RED = 91
    BRIGHT_GREEN = 92
    BRIGHT_YELLOW = 93
    BRIGHT_BLUE = 94
    BRIGHT_MAGENTA = 95
    BRIGHT_CYAN = 96
    BRIGHT_WHITE = 97


class SGR(AnsiEscapeCode, Enum):
    BOLD = 1
    FAINT = 2
    ITALIC = 3
    UNDERLINE = 4
    SLOW_BLINK = 5
    RAPID_BLINK = 6
    DOUBLE_UNDERLINED = 21


class ColoredFormatter(logging.Formatter):

    COLORS = {
        logging.DEBUG: Color.BRIGHT_BLACK,
        logging.WARNING: Color.YELLOW,
        logging.ERROR: Color.RED,
        logging.CRITICAL: Color.RED & SGR.DOUBLE_UNDERLINED,
    }

    def format(self, record):
        color = self.COLORS.get(record.levelno, "")

        log_format = (
            f"{Special.RESET}{Color.GREEN}[%(asctime)s]  "
            f"{Special.RESET}{color}%(levelname)-8s | %(name)s - %(message)s "
            f"{Special.RESET}{Color.BRIGHT_BLACK}(%(filename)s:%(lineno)d)"
            f"{Special.RESET}"
        )

        formatter = logging.Formatter(log_format)
        return formatter.format(record)


class UserLogger:
    def __init__(self, logger: logging.Logger = None) -> None:
        if logger is None:
            # root logger
            self.logger = logging.getLogger(None)
        else:
            self.logger = logger

    def add_stderr(self, level=logging.INFO) -> UserLogger:
        handler = logging.StreamHandler(stream=sys.stderr)
        formatter = ColoredFormatter()
        handler.setFormatter(formatter)
        handler.setLevel(level)
        self.logger.addHandler(handler)
        self.logger.level = min(self.logger.level, level)
        return self
