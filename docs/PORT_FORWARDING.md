# Port forwarding на ZTE F680 — протокол

Реверс-инжиниринг изменения правил NAT (port forwarding) в веб-интерфейсе.
Чтение — обычный `menuData`; **изменения** требуют двух дополнительных
хитростей: one-time токен страницы и RSA-подпись тела.

## 1. Протокол (пошагово)

### 1.1. Логин

Обычный 3-шаговый SHA256-логин (`f680.client.F680.login`) — см. [API.md](API.md).
Устанавливает cookie + базовый `sess_token`.

### 1.2. Забрать one-time токен страницы

```
GET /?_type=menuView&_tag=portForwarding
```

**Внимание: это ID МЕНЮ-СТРАНИЦЫ (`portForwarding`), а НЕ `.lua`!**

В HTML страницы вшит одноразовый токен в виде hex-escaped JS-строки:

```js
_sessionTmpToken = "\x69\x54...";
```

Парсинг:

```python
import re
m = re.search(r'_sessionTmpToken = "((?:\\x[0-9a-f]{2})+)"', html)
token = m.group(1).encode().decode("unicode_escape")
```

**Этот токен — НЕ `sess_token` из логина.** Именно его надо отправлять как
`_sessionTOKEN` в теле POST. Каждое обращение к `menuView` выдаёт **новый**
токен; повторное использование устаревшего → `IF_ERRORID -1452`
«Страница устарела».

Поэтому в `f680.portforward` перед КАЖДЫМ POST делается свежий `menuView`
(`PortForward._view()`).

### 1.3. POST изменения

```
POST /?_type=menuData&_tag=firewall_portforwarding_lua.lua
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest
Check: base64(RSA-PKCS1v15(SHA256(body)))
```

Тело — urlencoded-форма:

```
IF_ACTION=...&_InstID=...&<поля правила>&_sessionTOKEN=<токен из 1.2>
```

**Заголовок `Check`**: SHA256-hex от **строки тела целиком** (как была
отправлена), затем RSA-PKCS1v15 шифрованием за **встроенным в роутер
публичным ключом** (`f680.portforward.PUBKEY`), base64. Криптография через
[pycryptodome](https://pycryptodome.readthedocs.io/):

```python
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

def rsa_check(body: str) -> str:
    digest = hashlib.sha256(body.encode()).hexdigest()
    cipher = PKCS1_v1_5.new(RSA.import_key(PUBKEY))
    return base64.b64encode(cipher.encrypt(digest.encode())).decode()
```

> Рядом в JS страниц есть ещё и **AES-CBC** (ZeroPadding, ключ и iv =
> SHA256 от 16-значных рандомов, пары RSA→encode-поле) для полей с
> атрибутом `encode="1"` — для port forwarding **не требуется**.

## 2. Модель правил

* Инстансы: `DEV.NAT.PtMapping<n>` (id виден в `_InstID`).
* `IF_ACTION`:
  | Value | Действие |
  |---|---|
  | `Apply` | создать (`_InstID=-1`) / изменить (существующий id) |
  | `Delete` | удалить правило |
  | `Cancel` | отменить изменения без сохранения |
  | `InstSwitch` | включить/отключить правило |

### Поля правила

| Поле | Описание |
|---|---|
| `Enable` | `1` / `0` — включено/выключено |
| `Alias` | человекочитаемое название правила |
| `Protocol` | `TCP` / `UDP` / `BOTH` |
| `RemoteHost` + `RemoteHostEndRange` | внешний IP; `0.0.0.0` = любой |
| `AllInterface` | `1` — все WAN-интерфейсы |
| `ExternalPort` (+ `ExternalPortEndRange`) | внешний порт / диапазон |
| `InternalClient` | IP устройства в LAN |
| `InternalPort` (+ `InternalPortEndRange`) | внутренний порт / диапазон |

### Полный пример тела (создание)

```
IF_ACTION=Apply&_InstID=-1&Enable=1&Alias=test&Protocol=BOTH&RemoteHost=0.0.0.0
&RemoteHostEndRange=0.0.0.0&AllInterface=1&ExternalPort=3000&ExternalPortEndRange=3000
&InternalClient=192.168.1.3&InternalPort=3000&InternalPortEndRange=3000
&_sessionTOKEN=<one-time token>
```

### Двойное экранирование ответов ⚠️

Роутер **двойно экранирует** entity-значения в XML-ответах: alias
`test | py` приходит как `test&#32;|&#32;py`. Перед повторной отправкой
или сравнением раскрывать HTML-unescape **до устойчивости**:

```python
def unescape_stable(s):
    for _ in range(5):
        new = html.unescape(s)
        if new == s:
            break
        s = new
    return s
```

Именно так `PortForward.close_port` / `enable_port` / `set_alias` работают: читают
правило, делают `unescape_stable` для всех полей, меняют одно,
пересылают.

## 3. Python API (`f680.portforward.PortForward`)

```python
from f680 import PortForward

with PortForward() as pf:          # авто-login/logout
    pf.rules()                     # → [dict, ...] со всеми правилами
    pf.open_port(8080, "192.168.1.2", 8080, proto="both", alias="web")
    pf.close_port("web")           # Enable=0, правило остаётся
    pf.enable_port("web")          # Enable=1, правило снова активно
    pf.remove_port(8080)           # Delete
    pf.set_alias("web", "new name")
    pf.update_port("web", proto="tcp", int_port=8081)  # точечное изменение
```

* `open_port` **заменяет** правило, уже занимающее этот внешний порт
  (Apply на существующий id вместо создания нового).
* `close_port` / `enable_port` / `remove_port` / `set_alias` ищут правило по
  внешнему порту (число, включая попадание в диапазон), stable id
  (`DEV.NAT.PtMapping1`) или по alias (регистр не важен, точное совпадение).
* `update_port(ref, **changes)` — точечное изменение полей существующего
  правила: `alias`, `proto` (tcp|udp|both), `int_ip`, `remote_host`,
  `ext_port`, `ext_port_end`, `int_port`, `int_port_end`, `enabled` (bool).
  Не переданные поля сохраняются; запись (stable id) при этом **не
  меняется** — это modify, а не «удали и создай».* Диапазоны портов: `ext_port_end` / `int_port_end`.
* Ограничение внешнего IP: `remote_host` (по умолчанию `0.0.0.0` = любой).

## 4. CLI

```bash
f680 ports list
f680 ports add --port 3000 --ip 192.168.1.3 --in-port 3000 --name "PC | Open WebUI"
f680 ports add --port 22 --ip 192.168.1.2 --in-port 22 --proto tcp
f680 ports add --port 50000-60000 --ip 192.168.1.5 --in-port 5000-15000 --proto udp
f680 ports disable 3000
f680 ports enable 3000
f680 ports remove "PC | Open WebUI"    # спросит y/n; -y — пропустить
f680 help ports add                    # подробная справка по параметрам
```

Формат `add` — только флаги: `--port N` `--ip IP` `--in-port N` +
`--name TEXT`, `--proto tcp|udp|both`, `--port-end N`, `--in-port-end N`,
`--from IP`. `--port` / `--in-port` принимают одно значение или диапазон
(`1000-2000`) — конец диапазона подставляется автоматически, если
`--port-end` / `--in-port-end` не заданы явно. Все параметры подробно
описаны в `f680 help ports add`. Ссылки REF (в `disable` / `enable` /
`remove` / `modify` / `rename`): № из списка, внешний порт, id или название.

## 5. Ошибки

| Симптом | Причина |
|---|---|
| `IF_ERRORID -1452` «Страница устарела» | повторное использование `_sessionTmpToken` — нужно свежее `menuView` перед каждым POST |
| `SessionTimeout` в IF_ERRORSTR | сессия не разогрета (`GET /` после логина) или токен просрочен |
| ошибка подписи при POST | `Check` считается от тела, которое будет отправлено **точно** (порядок полей, urlencoding) |
