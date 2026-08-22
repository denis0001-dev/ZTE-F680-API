"""
f680.cli.ui — цвета терминала и человекочитаемые ошибки.

Цвета включаются автоматически, только если stdout — TTY.
В трубе/пайпе (``f680 ports list | grep x``) и при переменной
``NO_COLOR`` вывод чистый.

Вручную:
    F680_COLOR=1  — всегда в цвете
    F680_COLOR=0  — никогда
"""

import os
import sys

# ---------------------------------------------------------------------------
# Цвета
# ---------------------------------------------------------------------------

_CODES = {
    "reset": "0", "bold": "1", "dim": "2",
    "red": "31", "green": "32", "yellow": "33", "blue": "34",
    "magenta": "35", "cyan": "36",
}


def color_enabled():
    """Цвета на? (TTY + нет NO_COLOR, либо явный F680_COLOR)."""
    flag = os.environ.get("F680_COLOR")
    if flag is not None:
        return flag != "0"
    if os.environ.get("NO_COLOR") is not None:
        return False
    try:
        return sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def paint(s, *styles):
    """Закрасить строку стилями (bold, red, dim, ...). Бесцветно если нет TTY."""
    s = str(s)
    if not color_enabled() or not styles:
        return s
    codes = ";".join(_CODES[st] for st in styles)
    return f"\x1b[{codes}m{s}\x1b[0m"


def bold(s):
    return paint(s, "bold")


def dim(s):
    return paint(s, "dim")


def red(s):
    return paint(s, "red")


def green(s):
    return paint(s, "green")


def yellow(s):
    return paint(s, "yellow")


def cyan(s):
    return paint(s, "cyan")


# ---------------------------------------------------------------------------
# Печать сообщений
# ---------------------------------------------------------------------------

def ok(msg):
    """Успех: зелёная галочка + текст."""
    print(green("✓ ") + msg)


def info(msg):
    """Нейтральное сообщение."""
    print(msg)


def warn(msg):
    """Предупреждение: жёлтый треугольник."""
    print(yellow("⚠ ") + msg)


def fail(msg, hint=None):
    """Красивая ошибка в stderr:

        ✗ <сообщение>
          → <подсказка>

    Цветные иконы при TTY, чистый текст в трубе.
    """
    print(red("✗ ") + bold(msg), file=sys.stderr)
    if hint:
        print(paint("  → ", "dim") + hint, file=sys.stderr)


# ---------------------------------------------------------------------------
# Исключения CLI-слоя
# ---------------------------------------------------------------------------

class RefError(Exception):
    """Ссылка (порт/имя/индекс) не разрешается в правило.

    Разделяет «не найдено/неоднозначно» от ошибок роутера, чтобы
    показать точную подсказку.
    """
