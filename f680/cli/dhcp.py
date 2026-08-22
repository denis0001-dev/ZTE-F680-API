#!/usr/bin/env python3
"""
f680.cli.dhcp — DEPRECATED-обёртка над единым CLI `f680`.

Старый `f680-dhcp <cmd>` теперь транслируется в `f680 dhcp <cmd>`.
Новый синтаксис: `f680 dhcp --help`.
"""

import sys

from f680.cli.compat import main_dhcp

if __name__ == "__main__":
    sys.exit(main_dhcp())
