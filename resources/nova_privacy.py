"""Что можно записывать на диск, а что нельзя.

`temp/` — первое, что пользователь прикладывает к отчёту о проблеме, и первое,
что попадает в чужие руки вместе с ним. Всё, что туда пишется, надо считать
опубликованным.

Два вида данных опознают человека, а не программу:

* **Имя пользователя Windows** внутри пути. Программа, установленная в профиль,
  живёт по `C:\\Users\\ivan\\AppData\\...`, и это имя из отчёта уже не убрать.
  Для классификации приложения нужен хвост пути, а не начало, поэтому начало
  заменяется целиком.
* **Публичный адрес провайдера**. Не адрес выхода VPN — тот как раз общий и ничего
  не выдаёт, — а тот, который выдал оператор связи. По нему абонент
  устанавливается запросом к провайдеру.

Всё остальное, что нашлось в реальном `temp/` установленной 1.38, к личности не
ведёт: приватные адреса сети (RFC 1918), пути установки вне профиля, PID'ы,
и ключи AWG — последние сверены с поставляемым пулом и оказались общими для всех,
а не персональными.
"""

import os
import re

__all__ = [
    "USER_PROFILE_PLACEHOLDER",
    "redact_user_path",
    "redact_user_paths_in_text",
    "mask_provider_ip",
]

USER_PROFILE_PLACEHOLDER = "%USERPROFILE%"

# `X:\Users\<кто-то>\` в любом регистре и с любым из двух разделителей. Ловим не
# только собственный профиль: путь чужого процесса приезжает сюда так же, а под
# SYSTEM своего профиля вовсе нет.
_ANY_USER_DIR = re.compile(r"(?i)\b([A-Za-z]:[\\/]{1,2})Users\1?[\\/]{0,2}?([^\\/\r\n\"',;)]+)")
_USERS_PREFIX = re.compile(r"(?i)([A-Za-z]:[\\/])Users([\\/])([^\\/\r\n\"',;)]+)")


def _own_profile():
    value = os.environ.get("USERPROFILE") or ""
    return value.rstrip("\\/")


def redact_user_path(path):
    r"""`C:\Users\ivan\AppData\Local\Programs\X\x.exe` -> `%USERPROFILE%\AppData\...`

    Заменяется только начало. Хвост — `AppData\Local\Programs\Telegram Desktop\
    Telegram.exe` — это то, по чему приложение и опознаётся
    (`_app_family_from_app_id` ищет подстроки вроде `telegram desktop`), так что
    урезать его нельзя.

    Ничего не делает с путями вне профиля: `D:\Games\...` не про личность.
    """
    text = str(path or "")
    if not text:
        return text
    own = _own_profile()
    if own:
        lowered = text.lower()
        marker = own.lower()
        at = lowered.find(marker)
        if at >= 0:
            end = at + len(marker)
            # Только если дальше действительно граница пути, а не продолжение
            # имени: `C:\Users\ivan` не должен съедать `C:\Users\ivanov`.
            if end >= len(text) or text[end] in "\\/":
                return text[:at] + USER_PROFILE_PLACEHOLDER + text[end:]
    # Профиль другого пользователя (или своего, но записанный иначе).
    return _USERS_PREFIX.sub(lambda m: m.group(1) + "Users" + m.group(2) + "<user>", text, count=1)


def redact_user_paths_in_text(text):
    """То же самое, но внутри произвольной строки лога.

    Строка может нести и путь, и всё остальное: `app=C:\\Users\\ivan\\...` рядом
    с адресами и портами. Здесь заменяются все вхождения, а не первое.
    """
    value = str(text or "")
    if not value:
        return value
    own = _own_profile()
    if own:
        value = re.sub(re.escape(own) + r"(?=[\\/]|$)", USER_PROFILE_PLACEHOLDER, value, flags=re.I)
    return _USERS_PREFIX.sub(lambda m: m.group(1) + "Users" + m.group(2) + "<user>", value)


def mask_provider_ip(ip_str):
    """Прячет **хозяйскую** половину адреса, а не сетевую.

    Обратное к тому, как это было написано раньше (`***.***.233.85`). Сетевая
    половина называет оператора и город — это про канал, и ради этого строка в
    логе и существует. Хозяйская называет абонента, и именно её выдаёт
    провайдер по запросу.

    Хэш вместо адреса тут не подходит и поэтому не используется: видимой /16
    хватает, чтобы перебрать 65536 кандидатов, так что любой короткий хэш
    восстанавливается вместе с ним.
    """
    value = str(ip_str or "").strip().strip("[]")
    if not value:
        return str(ip_str or "")
    parts = value.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return f"{parts[0]}.{parts[1]}.*.*"
    if ":" in value:
        groups = [g for g in value.split(":") if g]
        if len(groups) >= 2:
            return f"{groups[0]}:{groups[1]}:*"
        return "IPv6:*"
    return value
