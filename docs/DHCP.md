# DHCP-привязки (Static DHCP Binding) на ZTE F680 — протокол

Реверс-инжиниринг «Привязки DHCP» (MAC → IP) из веб-интерфейса:
*Локальная сеть → Локальная сеть → IPv4*. Изменения используют тот же
протокол, что и port forwarding (см. [PORT_FORWARDING.md](PORT_FORWARDING.md)):
one-time токен страницы + RSA-подпись тела. Чтение — обычный `menuData`.

## 1. Эндпоинты

| Что | URL |
|---|---|
| menuView (one-time токен) | `GET /?_type=menuView&_tag=lanMgrIpv4` |
| правила (рост) | `GET /?_type=menuData&_tag=Localnet_LanMgrIpv4_DHCPStaticRule_lua.lua` |
| аренды DHCP (кто реально получил IP) | `GET /?_type=menuData&_tag=Localnet_LanMgrIpv4_DHCPHostInfo_lua.lua` |
| изменения | `POST /?_type=menuData&_tag=Localnet_LanMgrIpv4_DHCPStaticRule_lua.lua` |

**Внимание: menuView — ID МЕНЮ-СТРАНИЦЫ `lanMgrIpv4`, а не `.lua`!**

Токен извлекается из HTML страницы тем же способом, что и для port
forwarding: hex-escaped JS-строка `_sessionTmpToken = "\x69\x54..."`
(`f680.portforward.parse_page_token`). Перед **каждым** POST берётся свежий
`menuView` — повторное использование токен устаревает.

### Тело POST

```
IF_ACTION=...&_InstID=...&Name=...&IPAddr=...&MACAddr=...&_sessionTOKEN=<one-time>
```

Заголовки — как для NAT: `X-Requested-With: XMLHttpRequest` и
`Check: base64(RSA-PKCS1v15(SHA256(body)))` (`f680.portforward.rsa_check`).
Без `Check` роутер молча игнорирует POST.

## 2. Модель правил

* Инстансы: `DEV.V4DHCP.Server.Pool1.Bind<n>` (id в `_InstID`).
* `IF_ACTION`: `Apply` (создать при `_InstID=-1` / изменить существующий),
  `Delete`, `Cancel`.
* Поля: `Name` (≤ 10 символов, см. ниже!), `IPAddr`, `MACAddr`.
* При создании с `_InstID=-1` обязательно поле
  `_InstNum = max(существующих BindN) + 1` — пробелы в нумерации
  не используются. Без `_InstNum` POST молча не создаёт правило.

## 3. Подводные камни (проверено эмпирически)

### 3.1. `Name` — не более 10 символов ⚠️

При длине 11+ первый POST получает `IF_ERRORID=-257 FAIL` и так
**бесконечно** (ретраи с бэкоффом не помогают — ошибка детерминирована).
Проверено: len 8/9/10 — OK, len 11/12 — FAIL (в т.ч. без дефисов:
`abcdefghijk`, `a1234567890` — FAIL). Клиент (`f680.dhcp`) отбрасывает
длинные имена заранее (`ValueError`, `NAME_MAX_LEN = 10`).

### 3.2. Одноразовый токен тратится и на чтение ⚠️

Каждый GET `menuData` (в т.ч. чтение правил) валидирует текущий
one-time токен страницы. После нескольких чтений подряд первый POST
получает `IF_ERRORID=-257`. Поэтому:

* один «снимок» (`reservations()`) на весь блок изменений,
* POST — строго сразу после свежего `menuView`
  (в `f680.dhcp` это делает `Dhcp._post()` сам).

### 3.3. Коммит-лаг

После любого изменения (и сразу после ребута роутера) следующие ~3-5 с
роутер отвечает `IF_ERRORID=-257` на любые изменения. `Dhcp._post()`
ретраит FAIL до 4 раз с паузой 3 с и свежим токеном, этого хватает.

## 4. Python API

```python
from f680 import Dhcp

with Dhcp() as d:
    d.reservations()
    d.set_reservation("192.168.1.6", "1c:f6:4c:a0:cc:96", name="Macbook")
    d.rename_reservation("192.168.1.6", "Mac")
    d.remove_reservation("192.168.1.6")
    d.active_hosts()
```

CLI: `f680 dhcp list|leases|set|remove|rename` (см. README).

## 5. Тесты

Интеграционный тест трогает **реальный** роутер: создаёт временную
привязку `192.168.1.199 → 00:00:00:00:00:ff` и удаляет её.

```bash
python3 tests/test_dhcp_integration.py
```
