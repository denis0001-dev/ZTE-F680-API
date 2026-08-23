# Учётные записи (Account) на ZTE F680 — протокол

Реверс-инжиниринг «Администрирование → Администрирование учётной записи»
из веб-интерфейса: список учётных записей, **смена пароля** и время простоя
веб-сессии. Изменения используют тот же протокол, что и port forwarding /
firewall (см. [PORT_FORWARDING.md](PORT_FORWARDING.md), [FIREWALL.md](FIREWALL.md)):
one-time токен страницы + RSA-подпись тела.

## 1. Эндпоинты

| Что | URL |
|---|---|
| menuView (one-time токен) | `GET /?_type=menuView&_tag=accountMgr` |
| учётные записи (чтение) | `GET /?_type=menuData&_tag=devauth_accountmgr_lua.lua` |
| учётные записи (изменение) | `POST /?_type=menuData&_tag=devauth_accountmgr_lua.lua` |
| таймаут сессии (чтение) | `GET /?_type=menuData&_tag=web_login_timeout_lua.lua` |
| таймаут сессии (изменение) | `POST /?_type=menuData&_tag=web_login_timeout_lua.lua` |

Токен — hex-escaped JS-строка `_sessionTmpToken` на menuView-странице
(`f680.portforward.parse_page_token`). Перед **каждым** POST (и каждым GET
данных!) берётся свежий `menuView` — обычный сессионный токен для
`accountMgr` **не работает** (даёт `SessionTimeout`), как и в firewall.

### Тело POST

```
# смена пароля
IF_ACTION=Apply&_InstID=IGD.AU1&Right=1&Enable=1&Username=mgts&Password=<old>&NewPassword=<new>&Keyword=&_sessionTOKEN=<one-time>

# таймаут сессии
IF_ACTION=Apply&_InstID=IGD&Timeout=10&_sessionTOKEN=<one-time>
```

Заголовки — как для NAT: `X-Requested-With: XMLHttpRequest` и
`Check: base64(RSA-PKCS1v15(SHA256(body)))` (`f680.portforward.rsa_check`).
Без `Check` роутер молча игнорирует POST.

## 2. Модель

* Учётные записи — **многоинстансный** блок `OBJ_USERINFO_ID`:
  `IGD.AU1` (администратор, обычно `mgts`), `IGD.AU2` (пользователь,
  обычно `user`). Отключённые записи имеют `Enable=0` — клиент их
  отфильтровывает в `Account.accounts()`.
* Поля записи: `Right` (`1` = admin, `2` = user), `Enable` (0/1),
  `Username` (1..256, ASCII), `Password` (текущий, при смене),
  `NewPassword` (новый), `Keyword` (символы-подсказка, обычно пусто).
  Пароли в GET-ответ не отдаются.
* Требования к новому паролю (JS-валидатор страницы): **не меньше 8
  символов, только ASCII**, не связан с именем пользователя.
* Таймаут — одиночный инстанс `IGD` в блоке `OBJ_USERIF_ID`, поле
  `Timeout` (1..30 минут, дефолт 5).

Значения лежат **внутри** `<Instance>` — чтение через `parse_instances`
(`Account._get`).

## 3. Подводные камни (проверено эмпирически)

### 3.1. Обычный сессионный токен не подходит ⚠️

GET/POST к `accountMgr` с `_sessionTOKEN` из логина дают
`IF_ERRORSTR=SessionTimeout`. Нужен one-time токен из menuView —
`Account._get()`/`_post()` берут свежий `menuView` перед каждой операцией.

### 3.2. Старая сессия умирает после первого логина с новым паролем ⚠️

Сама смена пароля текущую сессию **не рвёт** (можно сразу сделать ещё что-то).
Но как только кто-то (в том числе тот же роутер, другой клиент, наш тест)
логируется с **новым** паролем — прежняя сессия с «старым» паролем
выдавливается: последующие запросы старой сессии получают `SessionTimeout`,
а menuView — 404 (нелогично, но стабильно).

Практическое следствие: после `change_password()` и проверки логина с новым
паролем — **заливайтись заново** для следующих операций (тест делает это
намеренно, см. `tests/test_account_integration.py`).

### 3.3. Неудачные логин-попытки замедляют следующие ⚠️

Ошибка логина (в т.ч. логин «старым» паролем после смены) возвращает
`lockingTime` (2..60 с) — следующие попытки в это окно считаются
неудачными. В `F680.login` заложены 3 ретрая с паузой 3 с, что хватает для
кратких пауз; после серии неудач может потребоваться подождать дольше
(тест падал на первом логине после ~1 минутной блокировки).

### 3.4. Коммит-лаг

Как и в firewall: сразу после изменения роутер может ответить
`IF_ERRORID=-257` на следующее изменение. `Account._post()` ретраит 3 раза
с паузой 3 с и свежим токеном.

## 4. API

```python
from f680 import Account

with Account() as a:
    a.accounts()                  # [{'username': 'mgts', 'right': 'admin', ...}]
    a.timeout()                   # {'timeout': 5}
    a.set_timeout(10)             # 1..30 мин, возвращает новое состояние
    a.change_password("mgts", "old", "new")   # True
```

CLI:

```bash
f680 account list [-j]             # все учётные записи + таймаут
f680 account password [username]   # смена пароля (getpass, 3 промпта)
f680 account timeout               # показать время простоя сессии
f680 account set-timeout 10        # изменить (1..30)
```
