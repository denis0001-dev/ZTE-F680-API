# Wi-Fi (WLAN) на ZTE F680 — протокол

Реверс-инжиниринг «Безопасность → Wi-Fi» из веб-интерфейса: три data-блока —
радио 2.4 GHz (`DEV.WIFI.RD1`), радио 5 GHz (`DEV.WIFI.RD2`) и список
SSID/шифрование (`DEV.WIFI.AP1..AP8` + WPA/WEP-суб-инстансы). Изменения
используют тот же протокол, что и port forwarding / firewall / DHCP
(см. [PORT_FORWARDING.md](PORT_FORWARDING.md), [FIREWALL.md](FIREWALL.md)):
one-time токен страницы + RSA-подпись тела. Чтение — обычный `menuData`.

## 1. Эндпоинты

| Что | URL |
|---|---|
| menuView (one-time токен) | `GET /?_type=menuView&_tag=wlanBasic` |
| радио + канал (чтение/изменение) | `GET/POST /?_type=menuData&_tag=wlan_wlanbasicadconf_lua.lua` |
| вкл/выкл радио (из формы) | `POST /?_type=menuData&_tag=wlan_wlanbasiconoff_lua.lua` |
| SSID + шифрование (чтение/изменение) | `GET/POST /?_type=menuData&_tag=wlan_wlansssidconf_lua.lua` |

**Токен:** извлекается из HTML тем же способом, что и для port forwarding:
hex-escaped JS-строка `_sessionTmpToken = "\x69\x54..."`
(`f680.portforward.parse_page_token`). Перед **каждым** POST (и каждый
GET данных!) берётся свежий `menuView` — повторное использование устаревшего
токена даёт `IF_ERRORID=-1452` «Страница устарела».

### Тело POST

```
IF_ACTION=Apply&_InstID=DEV.WIFI.RD1&RadioStatus=1&Channel=NULL&...&_sessionTOKEN=<one-time>
IF_ACTION=Apply&_InstID=DEV.WIFI.AP1&ESSID=NewName&...&_sessionTOKEN=<one-time>
```

Заголовки — как для NAT/FW: `X-Requested-With: XMLHttpRequest` и
`Check: base64(RSA-PKCS1v15(SHA256(body)))` (`f680.portforward.rsa_check`).
Без `Check` роутер молча игнорирует POST.

## 2. Модель

* Инстансы:
  * `DEV.WIFI.RD1` / `DEV.WIFI.RD2` — радио 2.4/5 GHz;
  * `DEV.WIFI.AP1..AP8` — SSID (AP1..AP4 на 2.4, AP5..AP8 на 5 — привязка
    через поле `WLANViewName`);
  * `DEV.WIFI.APn.PSK1` / `.WEP1..4` — суб-инстансы ключей (в POST не
    пишутся отдельно, см. 3.4).
* `IF_ACTION`: `Apply` (изменить/сохранить). `InstSwitch` существует в
  JS-коде формы, но для этого роутера не работает — см. 3.1.
* Поля радио (block `wlan_wlanbasicadconf`): `RadioStatus` (0/1),
  `Channel` (число или строка `"NULL"`), `AutoChannelEnabled` (0/1),
  `BandWidth`, `TxPower`, `Standard`, `11nMode`, `QosType`, … — полный
  набор см. в выводе `WLAN.radios()[…]['raw']`.
* Поля SSID (block `wlan_wlansssidconf`): `Enable` (0/1), `ESSID` (имя),
  `ESSIDHideEnable` (скрытие), `MaxUserNum` (1..32), `BeaconType`
  (`11i`/`11r`/`None`), `WPAAuthMode`/`11iAuthMode`
  (`PSKAuthentication`/`802.1X`), `11iEncryptType`, `WPAEncryptType`,
  поля RADIUS-сервера, …

Значения лежат **внутри** `<Instance>` — чтение идёт через
`parse_instances` (`WLAN._get`).

### Состояние (pageData)

Состояние радио/SSID можно увидеть и через `f680 page wlan` (alias
`wlanBasic`), но API (`WLAN.radios`/`ssids`) читает те же блоки через
`menuData` — один протокол, меньше веток.

## 3. Подводные камни (проверено эмпирически)

### 3.1. `InstSwitch` — no-op ⚠️

Блок `wlan_wlanbasiconoff_lua.lua` (в JS-форме используется с
`IF_ACTION=InstSwitch`) отвечает `SUCC`, но `RadioStatus` **не меняет** —
роутер принимает переключение только через полный `Apply` на
`wlan_wlanbasicadconf_lua.lua` со **всеми** полями радио (так шлёт
веб-форма). Поэтому `set_radio()` берёт полный raw-снимок инстанса,
меняет только `RadioStatus` и шлёт всё остальное без изменений.

### 3.2. Автоканал → `Channel=NULL`

При `AutoChannelEnabled=1` веб-форма шлёт поле `Channel` как строку
`"NULL"` (буквально). Явный канал в этом случае игнорируется. Для явного
канала: 1..14 (2.4 GHz), 36..165 (5 GHz, без DFS-ограничений в RUI).

### 3.3. Одноразовый токен тратится и на чтение ⚠️

Каждый GET `menuData` валидирует current one-time токен страницы — как в
firewall/DHCP. `WLAN._get()` берёт свежий `menuView` перед каждым чтением;
`WLAN._post()` — перед каждым POST (и при каждом ретрае).

### 3.4. WPA-пароль — только как часть POST на AP ⚠️

Пароль WPA-PSK меняется **только** внутри комбинированного POST на
AP-инстанс: все поля AP + `_InstID_PSK=<APn>.PSK1` +
`KeyPassphrase=<пароль>` (так шлёт веб-форма). Отдельный POST на
суб-инстанс `DEV.WIFI.APn.PSK1` отклоняется с `IF_ERRORID=-8`.

Флаг `_PSKCONIG=Y` (есть в JS-форме) **не нужен**: с ним роутер применяет
пароль, но отвечает 404/SessionTimeout вместо XML — клиент его не шлёт.

Старый пароль роутер **не отдаёт** при чтении (только факт наличия),
поэтому «restore» пароля в тестах невозможен.

### 3.5. Коммит-лаг

После любого изменения роутер ~3 с отвечает `IF_ERRORID=-257` на любые
изменения. `WLAN._post()` ретраит до 4 раз с паузой 3 с и свежим токеном
(как в `f680.firewall`/`f680.dhcp`). При `SessionTimeout` в ответе —
автоматический перезалогин.

## 4. Python API

```python
from f680 import WLAN

with WLAN() as w:
    w.radios()              # {'DEV.WIFI.RD1': {'band','enabled','channel','auto_channel',…}, …}
    w.ssids()               # [{'id','n','alias','ssid','enabled','band','hidden','max_users',…}, …]
    w.set_radio("5", False) # вкл/выкл радио (2.4 | 5 | RD1/RD2)
    w.enable_radio("2.4")
    w.disable_radio("2.4")
    w.set_channel("5", 36)          # явный канал
    w.set_channel("5", auto=True)   # автоканал (Channel=NULL)
    w.set_ssid("AP1", "NewName")    # AP1..AP8, номер 1..8 или текущее имя
    w.set_passphrase("1", "secret") # WPA-PSK, 8..63 ASCII
    w.set_ap("1", enabled=False, hidden=True, max_users=8)
```

Все мутации возвращают **новое** состояние (перечитывают блок после POST —
защита от «не применилось»). Ссылка на AP разрешается по инстансу
(`DEV.WIFI.AP1`), номеру (`1..8`) или текущему SSID.

CLI: `f680 wlan list|on|off|ssid|passphrase|channel|ap` (см. README).

## 5. Тесты

Интеграционный тест трогает **реальный** роутер, но все «болтающиеся»
изменения делает на **выключенных** SSID (AP4 — 2.4 GHz, AP8 — 5 GHz):
смена пароля + SSID у AP4, вкл/выкл AP4, смена SSID у AP8, round-trip
5 GHz радио (off/on) и round-trip автоканала. Между операциями — паузы
по 3 с (коммит-лаг).

Ограничение: старый WPA-PSK AP4 не читается — после теста у AP4 остаётся
известный пароль `TestPsw123` (AP4 выключен, на сеть не влияет).

```bash
python3 tests/test_wlan_integration.py
```
