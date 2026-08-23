# Межсетевой экран (Firewall + anti-DoS) на ZTE F680 — протокол

Реверс-инжиниринг «Безопасность → Межсетевой экран» из веб-интерфейса:
два блока — **уровень FW** (Enable/Level) и **anti-DoS** (Enable/Threshold).
Изменения используют тот же протокол, что и port forwarding / DHCP
(см. [PORT_FORWARDING.md](PORT_FORWARDING.md), [DHCP.md](DHCP.md)):
one-time токен страницы + RSA-подпись тела. Чтение — обычный `menuData`.

## 1. Эндпоинты

| Что | URL |
|---|---|
| menuView (one-time токен) | `GET /?_type=menuView&_tag=firewall` |
| уровень FW (чтение) | `GET /?_type=menuData&_tag=firewall_config_lua.lua` |
| anti-DoS (чтение) | `GET /?_type=menuData&_tag=firewall_dos_lua.lua` |
| уровень FW (изменение) | `POST /?_type=menuData&_tag=firewall_config_lua.lua` |
| anti-DoS (изменение) | `POST /?_type=menuData&_tag=firewall_dos_lua.lua` |

Обе страницы — `.lua`-теги (в отличие от DHCP, где menuView —
`lanMgrIpv4`, а данные — отдельный `.lua`). Валидатор `Check` (RSA)
общий для обоих POST-эндпоинтов.

**Токен:** извлекается из HTML страницы тем же способом, что и для
port forwarding: hex-escaped JS-строка `_sessionTmpToken =
"\x69\x54..."` (`f680.portforward.parse_page_token`). Перед **каждым**
POST (и каждый GET данных!) берётся свежий `menuView` — повторное
использование устаревшего токена даёт `IF_ERRORID=-1452` «Страница
устарела».

### Тело POST

```
IF_ACTION=Apply&_InstID=IGD&Enable=1&Level=Low&_sessionTOKEN=<one-time>
IF_ACTION=Apply&_InstID=IGD&Enable=1&Threshold=200&_sessionTOKEN=<one-time>
```

Заголовки — как для NAT: `X-Requested-With: XMLHttpRequest` и
`Check: base64(RSA-PKCS1v15(SHA256(body)))`
(`f680.portforward.rsa_check`). Без `Check` роутер молча игнорирует POST.

## 2. Модель

* Инстанс: единственный, `_InstID=IGD` — для **обоих** блоков.
* `IF_ACTION`: `Apply` (изменить/сохранить).
* Поля уровня FW: `Enable` (0/1), `Level` (`Low`/`Middle`/`High`).
* Поля anti-DoS: `Enable` (0/1), `Threshold` (1..999, дефолт 100).

Значения лежат **внутри** `<Instance>` — `parse_top_values` их
отбрасывает, поэтому чтение идёт через `parse_instances`
(в `f680/firewall.py` это делает `Firewall._get`).

### Состояние (pageData)

Страница `firewall` отдаёт состояние через отдельный эндпоинт
`_tag=firewall_homepage` — он валидирует **обычный** сессионный токен
(`_sessionTOKEN` из логина), а не one-time токен меню. В XML — значения
обоих блоков. Для чтения состояния можно использовать его, но API
(`Firewall.config`/`dos`) читает те же блоки через `menuData` — один
протокол, меньше веток.

## 3. Подводные камни (проверено эмпирически)

### 3.1. Одноразовый токен тратится и на чтение ⚠️

Каждый GET `menuData` валидирует current one-time токен страницы — как в
DHCP. `Firewall._get()` берёт свежий `menuView` перед каждым чтением;
`Firewall._post()` — перед каждым POST. Повторно использовать токен
нельзя.

### 3.2. Коммит-лаг

После любого изменения (и сразу после ребута) роутер ~3-5 с отвечает
`IF_ERRORID=-257` на любые изменения. `Firewall._post()` ретраит до
4 раз с паузой 3 с и свежим токеном (как в `f680.dhcp`), этого хватает.

### 3.3. Выключенный FW не сбрасывает уровень ⚠️

`Enable=0` хранит `Level` (роутер не обнуляет его). Поэтому `enable()`
просто поднимает `Enable=1`, уровень остаётся прежним. Клиент при
каждом POST шлёт актуальный `Level`, чтобы не потерять его при
`set_config`-ах без `level=`.

### 3.4. Уровни — только Low/Middle/High

Семантические уровни фильтрации (`Level`), не пороги. Клиент мапит
`low`/`middle`/`high` → `Low`/`Middle`/`High`, неизвестное значение →
`ValueError` ещё до POST.

### 3.5. Порог anti-DoS 1..999

Клиент проверяет диапазон до запроса; значение `0` или `≥1000` —
`ValueError` (роутер отклоняет с `-257`).

## 4. Python API

```python
from f680 import Firewall

with Firewall() as fw:
    fw.config()           # {'enabled': True, 'level': 'low'}
    fw.dos()              # {'enabled': True, 'threshold': 100}
    fw.set_level("high")
    fw.enable()           # включить (уровень сохраняется)
    fw.disable()
    fw.set_dos(enabled=False)        # или threshold=, или оба
    fw.set_threshold(200)
```

`set_config(enabled=, level=)` / `set_dos(enabled=, threshold=)`
принимают только то, что передали, остальное берут из текущего
состояния. Все мутации возвращают **новое** состояние (перечитывают
блок после POST — защита от «не применилось»).

CLI: `f680 firewall list|enable|disable|level|dos` (см. README).

## 5. Тесты

Интеграционный тест трогает **реальный** роутер: снимает исходное
состояние → меняет уровень FW → вкл/выкл FW → меняет порог anti-DoS →
вкл/выкл anti-DoS → восстанавливает исходное состояние.

```bash
python3 tests/test_firewall_integration.py
```
