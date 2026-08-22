"""Запуск: `python -m f680 <команда> ...` — то же самое, что `f680 <команда>`."""

import sys

from f680.cli.main import main

if __name__ == "__main__":
    sys.exit(main())
