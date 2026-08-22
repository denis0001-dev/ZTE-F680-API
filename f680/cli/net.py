#!/usr/bin/env python3
"""
f680.cli.net — DEPRECATED-обёртка над единым CLI `f680`.

Старый `f680-net status|devices|pf|all|reboot` теперь транслируется
в `f680 status|devices|pf list|report|reboot`.
Новый синтаксис: `f680 --help`.
"""

import sys

from f680.cli.compat import main_net

if __name__ == "__main__":
    sys.exit(main_net())
