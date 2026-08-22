# API роутера ZTE F680 (DST/MGTS, русская прошивка)

Документация по веб-API роутера, полученная реверс-инжинирингом веб-интерфейса.
База: `http://192.168.1.1`.

---

## 1. Аутентификация

Логин — не обычная HTML-форма, а **трёхшаговый протокол** с хешированием
пароля SHA256 и одноразовым токеном.

### Шаг 1 — получить `sess_token`

```
GET /?_type=loginData&_tag=login_entry
```

Ответ JSON:

```json
{ "sess_token": "...", "loginErrMsg": "", "promptMsg": "", "lockingTime": 0 }
```

### Шаг 2 — получить одноразовый токен-соль

```
GET /?_type=loginData&_tag=login_token
```

Ответ XML:

```xml
<ajax_response_xml_root>44141798</ajax_response_xml_root>
```

Убираем теги → получаем числовый одноразовый токен.

### Шаг 3 — отправить захешированный пароль

```
POST /?_type=loginData&_tag=login_entry
Content-Type: application/x-www-form-urlencoded

action=login
Password=<sha256_hex(password + onetime_token)>
Username=<user>
_sessionTOKEN=<sess_token из шага 1>
```

Успех → JSON:

```json
{ "sess_token": "...", "login_need_refresh": true }
```

Ошибка → заполняется `loginErrMsg` (неверный логин/пароль) и/или
`promptMsg` (счётчик неудачных попыток) + `lockingTime`.

**ВАЖНО: хеш = SHA256(пароль + одноразовый токен из шага 2), а не просто
SHA256(пароль).**

### Детали, без которых не работает

* Сервер ставит cookie `SID` — **держать cookie jar живым** на всю
  сессию (в `f680/client.py` это `http.cookiejar.CookieJar`).
* **Разогрев сессии**: после логина сделать `GET /` (~199 KB главная), как
  это делает браузер. Без этого могут прилетать ложные `SessionTimeout`
  на первых `menuData`-запросах.
* Каждый запрос `menuData`/`hiddenData` требует
  `&_sessionTOKEN=<sess_token>` (из ответа логина, НЕ из шага 1).
* **Lockout**: серия неудачных логингов включает cooldown —
  `lockingTime` тикает вниз (~60 с). Ждать перед повтором.

## 2. Logout

```
GET /?_type=loginData&_tag=logout_entry
X-Requested-With: XMLHttpRequest
body: IF_LogOff=1
```

Ответ: `{"need_refresh": true}`.

Обратите внимание: это **GET с телом формы** — именно поэтому в
`F680._request` есть параметр `method`, форсирующий HTTP-глагол.

В библиотеке logout:

* метод `logout()` — безопасен к повторным вызовам;
* context manager `with F680() as c:` / `with PortForward() as pf:` →
  авто-login при входе, авто-logout при выходе (включая исключение/`sys.exit`);
* CLI-команда `logout` (логин → явный logout как тест).

Флага `--keep-session` нет: чтобы сессию оставить — просто не используй
`with`, зайди вручную `c.login()`.

## 3. Формат ответов

Все data-эндпоинты возвращают XML в обёртке
`<ajax_response_xml_root>`:

* **Успешные ответы ТОЖЕ содержат** `<IF_ERRORSTR>SUCC</IF_ERRORSTR>` —
  проверяй **значение**, а не наличие тега (функция `F680.has_error`).
* Реальные ошибки: `<IF_ERRORSTR>SessionTimeout</IF_ERRORSTR>` или другие
  не-SUCC значения.
* Данные — повторяющиеся блоки `<Instance>`, внутри пары
  `<ParaName>…</ParaName><ParaValue>…</ParaValue>`.
* Id инстанса — в поле `_InstID` (напр. `IGD`, `IGD.SV.VS1.VP1.VL1`,
  `DEV.NAT.PtMapping3`).

Пример ответа:

```xml
<ajax_response_xml_root>
  <IF_ERRORSTR>SUCC</IF_ERRORSTR>
  <Instance>
    <ParaName>RadioSwitch</ParaName><ParaValue>1</ParaValue>
    <ParaName>_InstID</ParaName><ParaValue>IGD</ParaValue>
  </Instance>
</ajax_response_xml_root>
```

Парсинг в `f680.client.F680.parse_instances`: список словарей
`{ParaName: ParaValue, ..., "_instid": ...}`.

## 4. Endpoints

### Login / session

| Method | URL | Назначение |
|---|---|---|
| GET | `/?_type=loginData&_tag=login_entry` | получить `sess_token` / проба состояния |
| GET | `/?_type=loginData&_tag=login_token` | одноразовый SHA256-salt токен |
| POST | `/?_type=loginData&_tag=login_entry` | логин (захешированный пароль) |
| GET | `/?_type=loginData&_tag=logout_entry` | logout (body `IF_LogOff=1`) |
| POST | `/?_type=loginData&_tag=modeswitch_entry` | переключение режима (body `IF_ModeSwitch`) |

### Language

| Method | URL | Назначение |
|---|---|---|
| POST | `/?_type=hiddenData&_tag=switchlang_entry` | смена языка (body `IF_LanguageSwitch`) |

### Страницы / меню

| Method | URL | Назначение |
|---|---|---|
| GET | `/?_type=menuView&_tag=<pageurl>` | полная HTML-страница меню |
| GET | `/?_type=menuData&_tag=<lua>.lua[&InstNum=N]&_sessionTOKEN=…` | структурированные XML-данные страницы |

### Hidden data

| Method | URL | Назначение |
|---|---|---|
| GET | `/?_type=hiddenData&_tag=accessdev_data` | список подключённых устройств |
| GET | `/?_type=hiddenData&_tag=sntp_data` | SNTP / часы |

## 5. Data-страницы (проверено, роль `mgts`)

| Alias в скриптах | Tag | Статус для `mgts` |
|---|---|---|
| `devinfo` | `devinfo_homepage_lua.lua` | ⚠️ `SessionTimeout` (нужен `telecomadmin`) |
| `wan` | `wan_homepage_lua.lua` | ⚠️ `SessionTimeout` (нужен `telecomadmin`) |
| `wlan` | `wlan_homepage_lua.lua` | ✅ Wi-Fi / радиомодуль / клиенты |
| `voip` | `voip_homepage_lua.lua` | ✅ VoIP/телефония |
| `firewall` | `firewall_homepage_lua.lua` | ✅ firewall / AntiDDoS |
| `usb` | `usb_homepage_lua.lua` | ✅ USB / FTP |
| `accessdev` | `accessdev_homepage_lua.lua&InstNum=5` | ✅ проводные LAN-клиенты |

### Примеры реальных данных (проверено на живой машине)

* Wi-Fi: `RadioSwitch=1` (включён)
* Firewall: `Level=Low`, `AntiAttack=1`
* USB FTP: `FtpEnable=0`, `ServerPort=21`
* VoIP: `IsOnline=0`, `VoIPRegStatus=0`
* Проводные клиенты: из `accessdev` (LAN-порты с AliasName LAN1/LAN2)
* Беспроводные клиенты: из `wlan` — IP / MAC / hostname каждого устройства

Разграничение страниц: **`wlan` = беспроводные клиенты + состояние
радио; `accessdev` = проводные LAN-клиенты.**

## 6. Учётные записи

| Учётка | Роль | Примечание |
|---|---|---|
| `mgts` / (из `.env`) | user-level | основная для скриптов; devinfo/wan недоступны |
| `admin` / ? | admin | при неверном пароле растёт счётчик «N failed attempts» |
| `telecomadmin` / (сменён) | super-admin | классический ZTE пароль `nE7jA%5m` здесь НЕ действует |

## 7. Примеры raw-запросов

```bash
# сырой XML страницы
f680-api raw "?_type=menuData&_tag=wan_homepage_lua.lua"

# hidden-данные
f680-api raw "?_type=hiddenData&_tag=accessdev_data"

# HTML-страница меню (в ней — one-time _sessionTmpToken, см. PORT_FORWARDING.md)
f680-api raw "?_type=menuView&_tag=portForwarding"
```

`raw()` сам подставляет `_sessionTOKEN`, если он ещё не в query string.
