#!/usr/bin/env python3
"""
f680.cli.api — DEPRECATED-обёртка над единым CLI `f680`.

Старый `f680-api <cmd>` теперь транслируется в `f680 <cmd>`.
Новый синтаксис: `f680 --help`.
"""

import sys

from f680.cli.compat import main_api

if __name__ == "__main__":
    sys.exit(main_api())
