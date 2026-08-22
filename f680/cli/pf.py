#!/usr/bin/env python3
"""
f680.cli.pf — DEPRECATED-обёртка над единым CLI `f680`.

Старый `f680-pf <cmd>` теперь транслируется в `f680 pf <cmd>`.
Новый синтаксис: `f680 pf --help`.
"""

import sys

from f680.cli.compat import main_pf

if __name__ == "__main__":
    sys.exit(main_pf())
