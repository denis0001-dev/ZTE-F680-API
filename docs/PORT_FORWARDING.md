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

Именно так `PortForward.close_port` / `set_alias` работают: читают
правило, делают `unescape_stable` для всех полей, меняют одно,
пересылают.

## 3. Python API (`f680.portforward.PortForward`)

```python
from f680 import PortForward

with PortForward() as pf:          # авто-login/logout
    pf.rules()                     # → [dict, ...] со всеми правилами
    pf.open_port(8080, "192.168.1.2", 8080, proto="both", alias="web")
    pf.close_port("web")           # Enable=0, правило остаётся
    pf.remove_port(8080)           # Delete
    pf.set_alias("web", "new name")
```

* `open_port` **заменяет** правило, уже занимающее этот внешний порт
  (Apply на существующий id вместо создания нового).
* `close_port` / `remove_port` ищут правило по внешнему порту (число,
  включая попадание в диапазон) или по alias (регистр не важен, точное
  совпадение).
* Диапазоны портов: `ext_port_end` / `int_port_end`.
* Ограничение внешнего IP: `remote_host` (по умолчанию `0.0.0.0` = любой).

## 4. CLI

```bash
f680 pf list
f680 pf open 3000 192.168.1.3 3000 "PC | Open WebUI"
f680 pf open 22 192.168.1.2 22 --proto tcp
f680 pf open 50000 192.168.1.5 5000 --ext-end 60000 --int-end 15000 --proto udp
f680 pf close 3000
f680 pf remove "PC | Open WebUI"
```

(Старый `f680-pf <cmd>` — deprecated-обёртка, транслируется в `f680 pf <cmd>`.)

Формат `open`: `open <ext-port> <ip> <int-port> [название]`, опции:
`--proto tcp|udp|both`, `--ext-end N`, `--int-end N`, `--from IP`.

## 5. Ошибки

| Симптом | Причина |
|---|---|
| `IF_ERRORID -1452` «Страница устарела» | повторное использование `_sessionTmpToken` — нужно свежее `menuView` перед каждым POST |
| `SessionTimeout` в IF_ERRORSTR | сессия не разогрета (`GET /` после логина) или токен просрочен |
| ошибка подписи при POST | `Check` считается от тела, которое будет отправлено **точно** (порядок полей, urlencoding) |
