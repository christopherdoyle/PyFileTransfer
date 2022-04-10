import argparse
from enum import Enum
from typing import Any, Sequence, Type


def add_verbose(parser):
    """Adds standardized verbose option to parser."""
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Increase logging information printed to screen.",
    )


class EnumAction(argparse.Action):
    """Argparse handling fors Enums."""

    _enum: Type[Enum]

    def __init__(self, **kwargs) -> None:
        enum_type = kwargs.pop("type")

        # check given type is an enum
        if enum_type is None:
            raise ValueError("Argument 'type' missing")

        if not issubclass(enum_type, Enum):
            raise TypeError("Expected type Enum, found %s", type(enum_type))

        kwargs.setdefault("choices", tuple(e.value for e in enum_type))

        super().__init__(**kwargs)

        # store the enum type so we can restore from it later
        self._enum = enum_type

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str | Sequence[Any] | None,
        option_string: str | None = None,
    ) -> None:
        # convert value into an enum
        value = self._enum(values)
        setattr(namespace, self.dest, value)
