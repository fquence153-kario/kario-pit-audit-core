"""Allow python -m kario_pit without depending on an installed console script."""
from kario_pit.cli_v09 import main

if __name__ == "__main__":
    raise SystemExit(main())
