import os
import pathlib
from typing import Union

PathLike = Union[str, os.PathLike]


def to_path(pathlike: PathLike) -> pathlib.Path:
    return pathlib.Path(pathlike)
