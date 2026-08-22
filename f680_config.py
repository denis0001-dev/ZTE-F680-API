"""
f680_config.py — конфигурация: .env + переокрющие env-переменные.

Чувствительные данные (IP роутера, логин, пароль) вынесены в .env:
  cp .env.example .env   # и отредактируй

Приоритет: переменные окружения > .env (рядом со скриптом, затем CWD) >
значения по умолчанию. Без .env всё работает по умолчанию:
  base http://192.168.1.1, пользователь mgts.
"""

import os

try:
    from dotenv import load_dotenv
except ImportError:      # python-dotenv не обязателен — читаем руками
    load_dotenv = None

# Имя роутера (по умолчанию — локальная сеть MGTS/DST).
DEFAULT_BASE = "http://192.168.1.1"
DEFAULT_USERNAME = "mgts"
DEFAULT_PASSWORD = ""     # без .env пароль обязателен (F680_PASSWORD)


def _load_env_files():
    """Загрузить .env: сначала рядом с этим модулем (репо), потом CWD."""
    if load_dotenv is None:
        return
    for path in (
        os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"),
        ".env",
    ):
        try:
            load_dotenv(path, override=False)
        except Exception:
            pass


def _load_env_fallback(path):
    """Мини-парсер .env на случай, когда python-dotenv не установлен."""
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip().strip('"').strip("'")
            os.environ.setdefault(k, v)


_load_env_files()
if load_dotenv is None:
    _load_env_fallback(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
    _load_env_fallback(os.path.join(os.getcwd(), ".env"))

# ---------------------------------------------------------------------------
# Итоговые значения (env > .env > default)
# ---------------------------------------------------------------------------
BASE = os.environ.get("F680_BASE", DEFAULT_BASE).rstrip("/")
USERNAME = os.environ.get("F680_USERNAME", DEFAULT_USERNAME)
PASSWORD = os.environ.get("F680_PASSWORD", DEFAULT_PASSWORD)
