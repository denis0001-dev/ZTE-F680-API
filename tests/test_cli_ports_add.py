#!/usr/bin/env python3
"""Unit-тесты CLI-синтаксиса `ports add` (без роутера).

Запуск: python tests/test_cli_ports_add.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from f680.cli import main as m


def test_positional():
    a = m.build_parser().parse_args(
        ["ports", "add", "3000", "192.168.1.3", "3000", "PC | Open WebUI"])
    m._merge_positional_add(a)
    m._apply_port_ranges(a)
    assert (a.port, a.ip, a.in_port, a.name) == (3000, "192.168.1.3", 3000, "PC | Open WebUI")
    assert a.port_end is None and a.in_port_end is None


def test_positional_range():
    a = m.build_parser().parse_args(
        ["ports", "add", "1000-2000", "192.168.1.3", "1000-2000"])
    m._merge_positional_add(a)
    m._apply_port_ranges(a)
    assert (a.port, a.port_end) == (1000, 2000)
    assert (a.in_port, a.in_port_end) == (1000, 2000)


def test_flags():
    a = m.build_parser().parse_args(
        ["ports", "add", "--port", "3000", "--ip", "1.2.3.4",
         "--in-port", "3000", "--name", "x"])
    m._merge_positional_add(a)
    m._apply_port_ranges(a)
    assert (a.port, a.ip, a.in_port, a.name) == (3000, "1.2.3.4", 3000, "x")


def test_mixed_positional_and_flags_errors():
    a = m.build_parser().parse_args(
        ["ports", "add", "3000", "1.2.3.4", "3000", "--port", "4000"])
    try:
        m._merge_positional_add(a)
    except ValueError:
        return
    raise AssertionError("смешивание позиций и флагов не отловлено")


def test_state_column():
    on = m._state({"enabled": True})
    off = m._state({"enabled": False})
    assert "включено" in on and "выключено" in off


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"  ✓ {name}")
    print("все тесты прошли")
