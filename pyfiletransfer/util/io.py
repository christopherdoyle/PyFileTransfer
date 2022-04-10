import os
import pathlib
from typing import Union

PathLike = Union[str, os.PathLike]


def to_path(pathlike: PathLike) -> pathlib.Path:
    return pathlib.Path(pathlike)


def parse_path(s: str) -> pathlib.Path:
    return pathlib.Path(s)


def user_data_directory(
    vendor: str,
    application: str,
) -> pathlib.Path:
    from . import nt

    return pathlib.Path(nt.get_win_folder()) / vendor / application
