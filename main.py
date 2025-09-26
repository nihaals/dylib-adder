from pathlib import Path

import click
import lief


def add_library(binary_path: Path, dylib_path: str) -> None:
    app = lief.parse(binary_path)

    if not app:
        raise click.ClickException("`lief.parse()` returned None")
    if not isinstance(app, lief.MachO.Binary):
        raise click.ClickException("Parsed file is not a Mach-O binary")

    app.add_library(dylib_path)
    app.remove_signature()
    app.write(binary_path)


@click.command()
@click.argument(
    "binary_path", type=click.Path(exists=True, dir_okay=False, writable=True, executable=True, path_type=Path)
)
@click.argument("dylib_path", type=click.Path(exists=True, dir_okay=False))
def main(binary_path: Path, dylib_path: str) -> None:
    add_library(binary_path, dylib_path)


if __name__ == "__main__":
    main()
