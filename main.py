from pathlib import Path

import click
import lief


def add_library(binary_path: Path, dylib_path: str) -> None:
    fat_binary = lief.MachO.parse(binary_path)
    if not fat_binary:
        raise click.ClickException("`lief.parse()` returned None")

    for binary in fat_binary:
        binary.add_library(dylib_path)
        binary.remove_signature()
    fat_binary.write(str(binary_path))


@click.command()
@click.argument(
    "binary_path", type=click.Path(exists=True, dir_okay=False, writable=True, executable=True, path_type=Path)
)
@click.argument("dylib_path", type=click.Path(exists=True, dir_okay=False))
def main(binary_path: Path, dylib_path: str) -> None:
    add_library(binary_path, dylib_path)


if __name__ == "__main__":
    main()
