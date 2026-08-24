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
  * `rules` / `open_port` / `close_port` / `enable_port` / `remove_port` / `set_alias`
    / `update_port` (изменить любые поля существующего правила)
  * диапазоны портов, протоколы tcp/udp/both, ограничение внешнего IP
  * под капотом: one-time `_sessionTmpToken` из menuView +
    `Check: base64(RSA-PKCS1v15(SHA256(body)))`
* **`f680.dhcp.Dhcp`** — статические **DHCP-привязки** (MAC → IP):
  * `reservations()` / `active_hosts()` / `set_reservation()` /
    `remove_reservation()` / `rename_reservation()` /
    `update_reservation` (изменить IP/MAC/имя существующей привязки)
  * тот же протокол, что и port forwarding: one-time токен `lanMgrIpv4` +
    RSA-подпись; ретраи на коммит-лаг `IF_ERRORID=-257`
  * ограничение: имя привязки ≤ **10 символов**
* **`f680.firewall.Firewall`** — **межсетевой экран** (уровень + anti-DoS):
  * `config()` / `dos()` — чтение, `set_level()` / `enable()` / `disable()`,
    `set_dos()` / `enable_dos()` / `disable_dos()` / `set_threshold()`
  * тот же протокол, что и port forwarding: one-time токен `firewall` +
    RSA-подпись; оба блока — одиночный инстанс `IGD`
* **`f680.account.Account`** — **учётные записи** (смена пароля, таймаут сессии):
  * `accounts()` / `timeout()` — чтение, `change_password(username, old, new)`,
    `set_timeout(минуты)`
  * тот же протокол: one-time токен `accountMgr` + RSA-подпись; ⚠️ после
    первого логина с новым паролем старая сессия выдавливается
* **`f680.wlan.WLAN`** — **Wi-Fi** (радио 2.4/5 GHz, SSID, канал, пароль):
  * `radios()` / `ssids()` — чтение; `set_radio()` / `set_channel()` /
    `set_ssid()` / `set_passphrase()` / `set_ap()`
  * тот же протокол: one-time токен `wlanBasic` + RSA-подпись;
    ⚠️ `InstSwitch` — no-op, радио меняется полным Apply со всеми полями;
    WPA-пароль — только внутри POST на AP
* **CLI** (отдельно от Python API) — **единый `f680`**
  * `f680` / `python -m f680` — все команды роутера в одном:
    `status`, `devices` (`--json`), `report` (`all`), `ports list|add|enable|disable|remove|modify|rename`,
    `dhcp list|leases|add|remove|modify|rename`, `firewall list|enable|disable|level|dos`,
    `account list|password|timeout|set-timeout`,
    `wlan list|on|off|ssid|passphrase|channel|ap`,
    `page <tag>`, `raw "<qs>"`, `pages`,
    `login`, `logout`, `reboot`, `reset`, `help [команда [подкоманда]]`
  * `ports add` — позиции `ПОРТ IP ВНУТР_ПОРТ [ИМЯ]` или эквивалентные флаги
    `--port N | N-M`, `--ip IP`, `--in-port N | N-M` (+ `--port-end`,
    `--in-port-end`, `--proto`, `--from`); смешивать позиции и флаги нельзя
  * `ports modify` — только флаги: `--port N | N-M`, `--ip IP`,
    `--in-port N | N-M` (+ `--port-end`, `--in-port-end`, `--name`, `--proto`,
    `--from`). Диапазон `1000-2000` можно записать прямо в порту/флаге
  * подробная справка: `f680 help` и `f680 help <команда> [подкоманда]`
  * ссылки на правила — по **№ из списка**, внешнему порту, IP/MAC, стабильному
    id (`DEV.NAT.PtMapping1`, `DEV.V4DHCP...Bind3`) или названию
  * перед изменением показывает правило, после — сверяет по стабильному id,
    что изменена именно та запись (защита от «перескакивающих» индексов)
  * деструктивные действия (`reboot`, `reset`, `ports remove`, `dhcp remove`,
    `ports modify`, `dhcp modify`) просят подтверждение в терминале:
    нажать `y` (без Enter); `-y / --yes` — пропустить (для скриптов).
    В Python API подтверждений нет.
  * цвета — только в терминале (TTY); в трубе/пайпе вывод чистый.
    `F680_COLOR=1/0` — принудительно, `NO_COLOR` — выключить
  * ошибки — человекочитаемо (`✗ сообщение` + `→ подсказка`), Ctrl+C —
    «прервано» с exit 130 без traceback
* **`f680.macvendor`** — оффлайн-определение вендора устройства:
  * OUI-таблица по первым 3 байтам MAC + эвристики по hostname
  * `mac_vendor(mac)`, `hostname_hint(hostname)`, `guess_device(mac, host)`

## Структура репозитория

```
f680-router/
├── f680/                        # пакет
│   ├── __init__.py              #   публичный API: F680, PortForward, Dhcp, Firewall
│   ├── config.py                #   конфигурация: .env + env (F680_BASE/USERNAME/PASSWORD)
│   ├── client.py                #   базовый клиент API (login, страницы, парсинг XML)
│   ├── portforward.py           #   port forwarding (token + RSA Check, модель правил)
│   ├── dhcp.py                  #   DHCP-привязки (token + RSA Check, ретраи, модель правил)
│   ├── firewall.py              #   межсетевой экран + anti-DoS (token + RSA Check)
│   ├── account.py               #   учётные записи: смена пароля, таймаут (token + RSA Check)
│   ├── wlan.py                  #   Wi-Fi: радио, SSID, канал, пароль (token + RSA Check)
│   ├── macvendor.py             #   вендоры по MAC (OUI + hostname-эвристики)
│   └── cli/                     #   командный интерфейс (argparse)
│       ├── main.py              #     f680: python -m f680
│       └── ui.py                #     цвета (TTY), pretty-ошибки, иконки
├── tests/
│   ├── test_pf_integration.py   # сквозной тест: add rule → verify → delete
│   ├── test_dhcp_integration.py # сквозной тест: add bind → verify → delete
│   ├── test_firewall_integration.py # сквозной тест: level/enable/dos → verify → restore
│   ├── test_account_integration.py  # сквозной тест: accounts/timeout → смена пароля → verify → restore
│   └── test_wlan_integration.py     # сквозной тест: passphrase/ssid/radio (AP4/AP8, 5 GHz) → restore
├── docs/
│   ├── API.md                   # документация по API роутера (auth, endpoints, XML)
│   ├── PORT_FORWARDING.md       # протокол port forwarding (токены, RSA, модель правил)
│   ├── DHCP.md                  # протокол DHCP-привязок (токен, _InstNum, коммит-лаг)
│   ├── FIREWALL.md              # протокол межсетевого экрана + anti-DoS
│   ├── ACCOUNT.md               # протокол учётных записей (смена пароля, таймаут)
│   └── WLAN.md                  # протокол Wi-Fi (радио, SSID, InstSwitch-noop, пароль)
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
# вариант 1: как пакет (даёт консольный скрипт f680)
pip install -e .

# вариант 2: просто из каталога (python -m f680 ...)
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

Один бинарь `f680` на всё. Синтаксис: `f680 [опции] <команда> [аргументы]`.

```bash
# обзор домашней сети
f680 status          # состояние роутера (wifi/firewall/usb/voip)
f680 devices         # все клиенты + вендоры (wired и wifi)
f680 devices --json  # то же самое в JSON
f680 report          # полный отчёт: status + devices + ports + dhcp
f680 report --json

# подключение/разыскание
f680 login           # тест логина
f680 pages           # список известных страниц
f680 page wlan       # дамп любой data-страницы (есть --json)
f680 raw "?_type=menuData&_tag=wan_homepage_lua.lua"   # сырой запрос
```

```bash
# статические DHCP-привязки (MAC -> IP)
f680 dhcp list                       # все привязки
f680 dhcp leases                     # кто реально получил IP (DHCP-аренды)
f680 dhcp add 192.168.1.6 1c:f6:4c:a0:cc:96 Macbook
f680 dhcp modify 4 --name Mac         # № из списка (см. dhcp list)
f680 dhcp modify 192.168.1.6 --name Macbook
f680 dhcp rename 192.168.1.6 Mac     # имя <= 10 символов!
f680 dhcp remove 1 -y                 # № или IP/MAC/id/имя; спросит y/n
```

```bash
# межсетевой экран (уровень + anti-DoS)
f680 firewall list                    # состояние FW и anti-DoS
f680 firewall level middle            # low | middle | high
f680 firewall disable                 # выключить межсетевой экран
f680 firewall enable                  # включить (уровень сохраняется)
f680 firewall dos list                # состояние anti-DoS
f680 firewall dos set 200             # порог (1..999, по умолчанию 100)
f680 firewall dos disable
f680 account list                    # учётные записи + таймаут сессии
f680 account password mgts           # смена пароля (3 промпта getpass)
f680 account set-timeout 10          # время простоя сессии (1..30 мин)
```

```bash
# Wi-Fi (радио 2.4/5 GHz, SSID, канал, пароль)
f680 wlan list                       # радио + все SSID (есть --json)
f680 wlan off 5                      # выключить радио 5 GHz
f680 wlan on 5                       # включить обратно
f680 wlan ssid AP1 "NewName"         # AP1..AP8, номер 1..8 или текущее имя
f680 wlan passphrase AP1             # WPA-пароль (8..63 ASCII; без аргумента спросит)
f680 wlan channel 5 36               # явный канал (2.4: 1..14, 5: 36..165)
f680 wlan channel 5 --auto           # автоканал
f680 wlan ap 1 --disable --hide      # вкл/выкл и скрытие SSID
```

```bash
# правила проброса портов (NAT)
f680 ports list
f680 ports add 3000 192.168.1.3 3000 "PC | Open WebUI"    # позиции: ПОРТ IP ВНУТР. ПОРТ [ИМЯ]
f680 ports add 22 192.168.1.2 22 --proto tcp
f680 ports add 50000-60000 192.168.1.5 5000-15000 --proto udp   # диапазоны
f680 ports add --port 3000 --ip 192.168.1.3 --in-port 3000 --name "PC | Open WebUI"  # то же флагами
f680 ports modify 1 --proto tcp --in-port 2223   # № из списка
f680 ports modify 2222 --port 22220              # или внешний порт
f680 ports disable 3000              # отключить (правило остаётся)
f680 ports enable 3000               # включить обратно
f680 ports remove "PC | Open WebUI"  # спросит y/n
f680 ports remove "PC | Open WebUI" -y
f680 ports rename 3000 "New Name"
f680 help ports add                  # подробная справка по любой команде
```

```bash
# перезагрузить роутер и дождаться, пока он поднимется (спросит y/n)
f680 reboot
f680 reboot -y

# сброс настроек к заводским (всё сотрётся!)
f680 reset -y
```

Все команды используют context manager — логин и **автоматический
logout** (даже при ошибке), на роутере не висит мёртвая сессия.

`-j/--json` поддерживается там, где есть данные для выгрузки: `status`,
`devices`, `report`, `page`, `ports list`, `ports add`, `dhcp list`,
`dhcp leases`, `dhcp add`, `firewall list`. Ошибки — в stderr, exit code: 0 = OK,
1 = ошибка, 2 = не удалось залогиниться, 3 = действие отменено
(не подтверждено), 130 = прервано (Ctrl+C).

### Ссылки на правила

`enable` / `disable` / `remove` / `modify` / `rename` принимают:

* **№ из списка** (1..N в `ports list` / `dhcp list`) — самый простой вариант
* для `ports`: внешний порт, стабильный id (`DEV.NAT.PtMapping1`) или название
* для `dhcp`: IP, MAC, стабильный id (`DEV.V4DHCP.Server.Pool1.Bind3`) или название

Перед изменением CLI показывает правило, после — перечитывает его по
**стабильному id** и сверяет ожидаемые значения, поэтому «перескочившие»
индексы не приведут к изменению не той записи.

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
    pf.update_port("web", proto="tcp", int_port=8081)  # точечное изменение
    pf.close_port("web")
    pf.enable_port("web")
    pf.remove_port(8080)
```

```python
from f680 import Firewall

with Firewall() as fw:
    print(fw.config())   # {'enabled': True, 'level': 'low'}
    print(fw.dos())      # {'enabled': True, 'threshold': 100}
    fw.set_level("high")
    fw.disable_dos()
```

```python
from f680 import WLAN

with WLAN() as w:
    print(w.radios())    # состояние радио 2.4/5 GHz
    for s in w.ssids():  # все 8 SSID
        print(s["id"], s["ssid"], s["enabled"])
    w.set_ssid("AP1", "NewName")
    w.set_channel("5", auto=True)
    w.disable_radio("5")
```

Ошибки API — иерархия `F680Error` → `LoginFailed` / `RouterError`
(подклассы `RuntimeError` — старый код продолжает работать):

Чтобы сессию **оставить** (без авто-logout), просто зайди вручную:

```python
c = F680()
c.login()      # и не используй with — сессия жива
```

```python
from f680 import F680Error, LoginFailed, RouterError

try:
    ...
except LoginFailed:
    ...
except RouterError as e:
    ...
except F680Error:
    ...
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

`tests/test_firewall_integration.py` — сквозной тест межсетевого
экрана: чтение → смена уровня → вкл/выкл FW и anti-DoS → проверка →
восстановление исходного состояния.

`tests/test_account_integration.py` — сквозной тест учётных записей:
список → таймаут (смена/откат) → смена пароля `mgts` → логин с новым
паролем (новая сессия, т.к. старую выдавливает) → откат пароля →
логин с исходным.

`tests/test_wlan_integration.py` — сквозной тест Wi-Fi: все
«болтающиеся» изменения — на выключенных SSID (AP4/AP8): смена пароля +
SSID, вкл/выкл SSID, round-trip 5 GHz радио и автоканала → проверка →
восстановление (старый WPA-пароль AP4 нечитаем, остаётся `TestPsw123`).

```bash
python3 tests/test_pf_integration.py -v
python3 tests/test_dhcp_integration.py
python3 tests/test_firewall_integration.py
python3 tests/test_account_integration.py
python3 tests/test_wlan_integration.py
```

## Документация

* **[docs/API.md](docs/API.md)** — аутентификация (3 шага, lockout),
  формат XML-ответов, полная таблица endpoints, доступные страницы по ролям
* **[docs/PORT_FORWARDING.md](docs/PORT_FORWARDING.md)** — как устроен
  POST с RSA-подписью, one-time токены страниц, модель правил
  `DEV.NAT.PtMapping`, двойное экранирование сущностей
* **[docs/DHCP.md](docs/DHCP.md)** — протокол статических DHCP-привязок:
  эндпоинты, правило `_InstNum`, коммит-лаг `-257`, лимит имени в 10 символов
* **[docs/FIREWALL.md](docs/FIREWALL.md)** — протокол межсетевого экрана
  и anti-DoS: эндпоинты, инстанс `IGD`, поведение `firewall_homepage`
* **[docs/ACCOUNT.md](docs/ACCOUNT.md)** — протокол учётных записей:
  смена пароля (`_InstID=IGD.AU1/AU2`), таймаут сессии, выдавливание
  старой сессии после логина с новым паролем, `lockingTime` при
  неудачных попытках
* **[docs/WLAN.md](docs/WLAN.md)** — протокол Wi-Fi: радио
  `DEV.WIFI.RD1/RD2`, SSID `DEV.WIFI.AP1..AP8`, почему `InstSwitch` —
  no-op, `Channel=NULL` при автоканале, WPA-пароль только внутри POST
  на AP

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
