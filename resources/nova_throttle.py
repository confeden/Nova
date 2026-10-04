"""Классификация замедлений по диагностике detect_throttled_load.

Окно «замирания на 16 КБ» шире, чем 16-19 КБ: стенд 2026-10-04 видел обрыв
потока на 15.3-24.9 КБ тела ответа (15 701, 15 827, 16 101, 16 384, 17 613,
17 823, 19 084, 21 559, 22 895, 23 533, 25 468 байт). ТСПУ считает байты
сервера вместе с TLS-рукопожатием (сертификаты — ещё 3-6 КБ), поэтому граница
в теле ответа плавает. Прежний классификатор называл обрыв на 15 или 21 КБ
«Early_Timeout» и выбирал под него не ту boost-стратегию.
"""
import re

FREEZE_MIN_KB = 12
FREEZE_MAX_KB = 40

# Тело ответа короче этого не может показать замирание: поток кончается раньше.
FREEZE_OBSERVABLE_BYTES = 16000

_AT_KB = re.compile(r"(timeout|connection_closed|error|broken_pipe)_at_(\d+)kb")


def classify_throttle_type(diag_info):
    """Тип замедления для выбора boost-стратегии.

    Slow_DPI | DPI_16KB | TCP_RST | Early_Timeout | unknown
    """
    if not diag_info:
        return "unknown"
    d = str(diag_info).lower()
    if "slow_speed" in d:
        return "Slow_DPI"
    if "tcp_reset" in d:
        return "TCP_RST"
    m = _AT_KB.search(d)
    if m:
        kb = int(m.group(2))
        if FREEZE_MIN_KB <= kb <= FREEZE_MAX_KB:
            return "DPI_16KB"
        if m.group(1) == "timeout":
            return "Early_Timeout"
    return "unknown"


def is_freeze_diag(diag_info):
    return classify_throttle_type(diag_info) == "DPI_16KB"
