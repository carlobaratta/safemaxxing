"""PyInstaller entry point: run the Typer CLI as the frozen `safemaxxing` binary."""

from safemaxxing.cli import app

if __name__ == "__main__":
    app()
