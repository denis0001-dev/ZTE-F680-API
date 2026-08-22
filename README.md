# ZTE F680 (DST/MGTS) — клиент веб-API роутера

Полностью рабочий Python-клиент для админ-веб-API роутера **ZTE F680** с
русским фирменным ПО DST/МегаФон (MGTS). Реверс-инжиниринг протокола:
трёхшаговая SHA256-аутентификация, XML-ответы, одноразовые токены страниц
и RSA-подпись POST-запросов.

База: `http://192.168.1.1`

## Возможности

* **`f680.client.F680`** — базовый клиент API:
  * 3-шаговый login (SHA256 password + one-time token), logout, cookie-сессия
  * context manager: `with F680() as c:` — авто-login / авто-logout
  * чтение любых data-страниц (wlan, voip, firewall, usb, accessdev, …) с
    парсингом XML в словари (instances + top-level ParaName/ParaValue)
  * таблица подключённых клиентов: `connected_devices()` — **wired + Wi-Fi
    вместе** (дедуп по MAC, метка `source`), `wifi_clients()`, `lan_clients()`
  * `status()` — сводный снимок состояния: Wi-Fi radio, firewall, USB FTP,
    VoIP + список клиентов и ошибок страниц
  * `reboot()` — **перезагрузить роутер** (Succ → роутер поднимется через
    ~30–60 c), `factory_reset()` — сброс к заводским, `wait_online()` —
    дождаться, пока роутер снова примет HTTP
  * `unescape_stable()` — раскрывает двойное HTML-экранирование значений
* **`f680.portforward.PortForward`** — управление **port forwarding**:
  * `rules` / `open_port` / `close_port` / `remove_port` / `set_alias`
  * диапазоны портов, протоколы tcp/udp/both, ограничение внешнего IP
  * под капотом: one-time `_sessionTmpToken` из menuView +
    `Check: base64(RSA-PKCS1v15(SHA256(body)))`
* **`f680.dhcp.Dhcp`** — статические **DHCP-привязки** (MAC → IP):
  * `reservations()` / `active_hosts()` / `set_reservation()` /
    `remove_reservation()` / `rename_reservation()`
  * тот же протокол, что и port forwarding: one-time токен `lanMgrIpv4` +
    RSA-подпись; ретраи на коммит-лаг `IF_ERRORID=-257`
  * ограничение: имя привязки ≤ **10 символов**
* **CLI** (отдельно от Python API):
  * `f680-api` / `python -m f680.cli.api` — `login`, `logout`, `devices`,
    `page <tag>`, `raw "<qs>"`, `pages`, `reboot`, `reset --yes`
  * `f680-pf` / `python -m f680.cli.pf` — `list`, `open`, `close`, `remove`,
    `logout`
  * `f680-dhcp` / `python -m f680.cli.dhcp` — `list`, `leases`, `set`,
    `remove`, `rename`
  * `f680-net` / `python -m f680.cli.net` — **обзор домашней сети одной
    командой**: `status` (роутер), `devices` (клиенты + вендоры по MAC,
    `--json`), `pf` (проброс портов), `all` (полный отчёт)
* **`f680.macvendor`** — оффлайн-определение вендора устройства:
  * OUI-таблица по первым 3 байтам MAC + эвристики по hostname
  * `mac_vendor(mac)`, `hostname_hint(hostname)`, `guess_device(mac, host)`

## Структура репозитория

```
f680-router/
├── f680/                        # пакет
│   ├── __init__.py              #   публичный API: F680, PortForward
│   ├── config.py                #   конфигурация: .env + env (F680_BASE/USERNAME/PASSWORD)
│   ├── client.py                #   базовый клиент API (login, страницы, парсинг XML)
│   ├── portforward.py           #   port forwarding (token + RSA Check, модель правил)
│   ├── dhcp.py                  #   DHCP-привязки (token + RSA Check, ретраи, модель правил)
│   ├── macvendor.py             #   вендоры по MAC (OUI + hostname-эвристики)
│   └── cli/                     #   командные интерфейсы (argparse)
│       ├── api.py               #   f680-api:  python -m f680.cli.api
│       ├── pf.py                #   f680-pf:   python -m f680.cli.pf
│       ├── dhcp.py              #   f680-dhcp: python -m f680.cli.dhcp
│       └── net.py               #   f680-net:  python -m f680.cli.net
├── tests/
│   ├── test_pf_integration.py   # сквозной тест: add rule → verify → delete
│   └── test_dhcp_integration.py # сквозной тест: add bind → verify → delete
├── docs/
│   ├── API.md                   # документация по API роутера (auth, endpoints, XML)
│   ├── PORT_FORWARDING.md       # протокол port forwarding (токены, RSA, модель правил)
│   └── DHCP.md                  # протокол DHCP-привязок (токен, _InstNum, коммит-лаг)
├── .env.example                 # шаблон настроек (скопировать в .env)
├── pyproject.toml               # установка пакета + консольные скрипты
├── requirements.txt
└── README.md
```

Python API и CLI разделены: `f680/client.py` и `f680/portforward.py` —
чистые библиотеки без argparse/печати, `f680/cli/*` — тонкий слой команд
сверху.

## Установка

```bash
# вариант 1: как пакет (даёт консольные скрипты f680-api / f680-pf)
pip install -e .

# вариант 2: просто из каталога (python -m f680.cli.api ...)
pip install -r requirements.txt
```

Python 3.8+. Зависимости: pycryptodome (обязательно), python-dotenv
(опционален — без него `.env` парсится встроенным мини-парсером).

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
f680-api devices          # или: python -m f680.cli.api devices

# список известных страниц
f680-api pages

# дамп любой data-страницы
f680-api page wlan
f680-api page firewall

# сырой запрос
f680-api raw "?_type=menuData&_tag=wan_homepage_lua.lua"
```

```bash
# перезагрузить роутер и дождаться, пока он поднимется
f680-api reboot

# сброс настроек к заводским (всё сотрётся!)
f680-api reset --yes
```

```bash
# обзор домашней сети
f680-net status       # состояние роутера (wifi/firewall/usb/voip)
f680-net devices      # все клиенты + вендоры (wired и wifi)
f680-net devices --json
f680-net pf           # правила проброса портов
f680-net all          # полный отчёт одним заходом
```

```bash
# статические DHCP-привязки (MAC -> IP)
f680-dhcp list                       # все привязки
f680-dhcp leases                     # кто реально получил IP (DHCP-аренды)
f680-dhcp set 192.168.1.6 1c:f6:4c:a0:cc:96 Macbook
f680-dhcp rename 192.168.1.6 Mac     # имя <= 10 символов!
f680-dhcp remove 192.168.1.6

# правила проброса портов
f680-pf list
f680-pf open 3000 192.168.1.3 3000 "PC | Open WebUI"
f680-pf open 22 192.168.1.2 22 --proto tcp
f680-pf close 3000
f680-pf remove "PC | Open WebUI"
```

Все команды CLI используют context manager — логин и **автоматический
logout** (даже при ошибке), на роутере не висит мёртвая сессия.

### Использование как библиотеки

```python
from f680 import F680

with F680() as c:                      # авто-login / авто-logout
    devs = c.connected_devices()
    err, insts = c.get_page("wlan")    # (has_error, [dict, ...])
```

```python
from f680 import F680

c = F680()
c.login()
c.reboot()            # роутер перезагрузится
secs = c.wait_online(timeout=180)  # дождаться HTTP-доступности
# после reboot старая сессия мертва — зайдись заново:
c = F680()
c.login()
```

```python
from f680 import PortForward

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

`tests/test_dhcp_integration.py` — сквозной тест DHCP-привязок:
логин → создание временной привязки `192.168.1.199` → проверка →
удаление. Тоже трогает **реальный** роутер.

```bash
python3 tests/test_pf_integration.py -v
python3 tests/test_dhcp_integration.py
```

## Документация

* **[docs/API.md](docs/API.md)** — аутентификация (3 шага, lockout),
  формат XML-ответов, полная таблица endpoints, доступные страницы по ролям
* **[docs/PORT_FORWARDING.md](docs/PORT_FORWARDING.md)** — как устроен
  POST с RSA-подписью, one-time токены страниц, модель правил
  `DEV.NAT.PtMapping`, двойное экранирование сущностей
* **[docs/DHCP.md](docs/DHCP.md)** — протокол статических DHCP-привязок:
  эндпоинты, правило `_InstNum`, коммит-лаг `-257`, лимит имени в 10 символов

## Известные особенности

* Успешные ответы **содержат** `<IF_ERRORSTR>SUCC</IF_ERRORSTR>` — проверять
  значение, а не наличие тега.
* Каждому `menuData`/`hiddenData` нужен `_sessionTOKEN` из ответа логина;
  после логина стоит сделать `GET /`, чтобы «разогреть» сессию.
* При последовательных ошибках логина роутер включает cooldown
  (`lockingTime`, ~60 c) — ждать перед повтором.
* Для **изменений** (port forwarding, reboot) нужен **другой** токен:
  `_sessionTmpToken` из HTML menuView-страницы. Устаревший токен →
  `IF_ERRORID -1452` «Страница устарела». Подробности в
  [docs/PORT_FORWARDING.md](docs/PORT_FORWARDING.md).
* Управляющие действия (`IF_ACTION=Restart` / `Reset`) **требуют**
  заголовок `Check` (RSA) — без него POST молча игнорируется. Протокол тот
  же, что у port forwarding.
* После `reboot()` web-сессия умирает: для следующих запросов нужен свежий
  `login()`.
* Роутер **двойно экранирует** entity-значения в ответах (alias
  `test&#32;|&#32;py` приходит как `test&#32;|&#32;py`) — скрипты раскрывают
  HTML-unescape до устойчивости.
* **DHCP-привязки**: поле `Name` ограничено **10 символами** — длиннее →
  `IF_ERRORID=-257` (не зависит от символов в имени).
* После любых изменений (и сразу после ребута) роутер ~3-5 с отвечает
  `-257` на любые изменения — «коммит-лаг». `Dhcp._post()` ретраит с
  паузой 3 с и свежим токеном; при быстрой серии CRUD-операций это
  уже учтено внутри API.

## Лицензия

MIT
