"""Entrypoint: `python -m sureguard_code_scanner` or the `sureguard-code-scanner` script."""

from .server import main

if __name__ == "__main__":
    main()


# Re-exported for the console-script entrypoint.
__all__ = ["main"]
