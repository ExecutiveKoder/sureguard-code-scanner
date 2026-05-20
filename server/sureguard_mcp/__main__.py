"""Entrypoint: `python -m sureguard_mcp` or the `sureguard-mcp` script."""

from .server import main

if __name__ == "__main__":
    main()


# Re-exported for the console-script entrypoint.
__all__ = ["main"]
