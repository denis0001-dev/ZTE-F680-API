# ZTE F680 (DST/MGTS) — клиент веб-API роутера

Полностью рабочий Python-клиент для админ-веб-API роутера **ZTE F680** с
русским фирменным ПО DST/МегаФон (MGTS). Реверс-инжиниринг протокола:
трёхшаговая SHA256-аутентификация, XML-ответы, одноразовые токены страниц
и RSA-подпись POST-запросов.

База: `http://192.168.1.1`

## Возможности

* **`f680_api.py`** — базовый клиент API:
  * 3-шаговый login (SHA256 password + one-time token), logout, cookie-сессия
  * context manager: `with F680() as c:` — авто-login / авто-logout
  * чтение любых data-страниц (wlan, voip, firewall, usb, accessdev, …) с
    парсингом XML в словари
  * таблица подключённых клиентов (IP / MAC / hostname)
  * CLI: `login`, `logout`, `devices`, `page <tag>`, `raw "<qs>"`, `pages`
* **`f680_pf.py`** — управление **port forwarding** (реверс-инжиниринг):
  * `list` — таблица правил (порт, протокол, название, ip:порт, состояние)
  * `open` — создать/обновить правило (работает с портами и alias, без
    технических `PtMapping`-id)
  * `close` — отключить правило (`Enable=0`, правило остаётся)
  * `remove` — удалить правило
  * диапазоны портов, протоколы tcp/udp/both, ограничение внешнего IP
  * под капотом: one-time `_sessionTmpToken` из menuView +
    `Check: base64(RSA-PKCS1v15(SHA256(body)))`

## Структура репозитория

```
f680-router/
├── f680_config.py           # конфигурация: .env + env-переменные (F680_BASE/USERNAME/PASSWORD)
├── f680_api.py              # базовый клиент API (login, страницы, парсинг)
├── f680_pf.py               # port forwarding клиент (CLI + Python API)
├── .env.example             # шаблон настроек (скопировать в .env)
├── tests/
│   └── test_pf_integration.py   # сквозной тест: add rule → verify → delete
├── docs/
│   ├── API.md               # документация по API роутера (auth, endpoints, XML)
│   └── PORT_FORWARDING.md   # протокол port forwarding (токены, RSA, модель правил)
├── requirements.txt
└── README.md
```

## Установка

```bash
pip install -r requirements.txt     # нужен только pycryptodome
```

Python 3.8+ (стандартная библиотека + pycryptodome; python-dotenv опционален —
без него `.env` парсится встроенным мини-парсером).

### Настройки (.env)

Чувствительные данные — в `.env` (в git не попадает, см. `.env.example`):

```bash
cp .env.example .env    # и вписать F680_PASSWORD
```

| Переменная | По умолчанию | Описание |
|---|---|---|
| `F680_BASE` | `http://192.168.1.1` | адрес роутера |
| `F680_USERNAME` | `mgts` | логин |
| `F680_PASSWORD` | — (обязательно) | пароль |

Приоритет: переменные окружения > `.env` > значения по умолчанию.
CLI-флаги `--base` / `--user` / `--pass` переопределяют всё.

## Быстрый старт

```bash
# подключённые клиенты
python3 f680_api.py devices

# список известных страниц
python3 f680_api.py pages

# дамп любой data-страницы
python3 f680_api.py page wlan
python3 f680_api.py page firewall

# сырой запрос
python3 f680_api.py raw "?_type=menuData&_tag=wan_homepage_lua.lua"
```

```bash
# правила проброса портов
python3 f680_pf.py list
python3 f680_pf.py open 3000 192.168.1.3 3000 "PC | Open WebUI"
python3 f680_pf.py open 22 192.168.1.2 22 --proto tcp
python3 f680_pf.py close 3000
python3 f680_pf.py remove "PC | Open WebUI"
```

Все команды CLI используют context manager — логин и **автоматический
logout** (даже при ошибке), на роутере не висит мёртвая сессия.

### Использование как библиотеки

```python
from f680_api import F680

with F680() as c:                      # авто-login / авто-logout
    devs = c.connected_devices()
    err, insts = c.get_page("wlan")    # (has_error, [dict, ...])
```

```python
from f680_pf import PortForward

with PortForward() as pf:
    for r in pf.rules():
        print(r["alias"], r["ext_port"], r["int_ip"])
    pf.open_port(8080, "192.168.1.2", 8080, proto="both", alias="web")
    pf.close_port("web")
    pf.remove_port(8080)
```

Чтобы сессию **оставить** (без авто-logout), просто зайди вручную:

```python
c = F680()
c.login()      # и не используй with — сессия жива
```

## Учётные данные

Логин/пароль/IP берутся из `.env` (см. выше), не захардкожены.
`mgts` — **user-level** роль: страницы `devinfo` и `wan` возвращают
`SessionTimeout` (нужен `telecomadmin`). Остальные (wlan, voip, firewall,
usb, accessdev, port forwarding) работают. Подробности — в
[docs/API.md](docs/API.md).

## Тест

`tests/test_pf_integration.py` — сквозной тест port forwarding:
логин → чтение правил → создание тестового правила (порт 18080) →
проверка → удаление → logout. **Внимание:** тест создаёт и удаляет
реальное правило на живом роутере.

```bash
python3 tests/test_pf_integration.py -v
```

## Документация

* **[docs/API.md](docs/API.md)** — аутентификация (3 шага, lockout),
  формат XML-ответов, полная таблица endpoints, доступные страницы по ролям
* **[docs/PORT_FORWARDING.md](docs/PORT_FORWARDING.md)** — как устроен
  POST с RSA-подписью, one-time токены страниц, модель правил
  `DEV.NAT.PtMapping`, двойное экранирование сущностей

## Известные особенности

* Успешные ответы **содержат** `<IF_ERRORSTR>SUCC</IF_ERRORSTR>` — проверять
  значение, а не наличие тега.
* Каждому `menuData`/`hiddenData` нужен `_sessionTOKEN` из ответа логина;
  после логина стоит сделать `GET /`, чтобы «разогреть» сессию.
* При последовательных ошибках логина роутер включает cooldown
  (`lockingTime`, ~60 c) — ждать перед повтором.
* Для **изменений** (port forwarding) нужен **другой** токен:
  `_sessionTmpToken` из HTML menuView-страницы. Устаревший токен →
  `IF_ERRORID -1452` «Страница устарела». Подробности в
  [docs/PORT_FORWARDING.md](docs/PORT_FORWARDING.md).
* Роутер **двойно экранирует** entity-значения в ответах (alias
  `test | py` приходит как `test&#32;|&#32;py`) — скрипты раскрывают
  HTML-unescape до устойчивости.

## Лицензия

MIT
