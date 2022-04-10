from typing import TypeVar

_T = TypeVar("_T")


def identity(x: _T) -> _T:
    return x
