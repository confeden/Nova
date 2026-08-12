"""Грубый портрет стратегии обхода: чем она атакует, как далеко бьёт, чем прикрыта.

Модуль вынесен из `nova.pyw` не ради красоты. Ту же классификацию делает
`nova-rs/crates/nova-zapret/src/diversity.rs`, и пока обе копии жили в разных
языках и разных файлах, сверить их было нечем. Теперь ни одна из копий не
считается эталоном: эталон — `docs/reference/strategy-niche-table.json`, Rust
его порождает, а обе стороны против него проверяются. Из `nova.pyw` вытащить
это было нельзя, пока классификация сидела внутри 27-тысячестрочного файла,
который pytest не может импортировать (при импорте он поднимает права и рисует
окно).

Оси намеренно грубые. Точное смещение разреза или число повторов меняют шансы
против конкретного DPI, но не класс DPI, и в описателе разбили бы сетку на
ячейки, отказывающие одинаково, — ровно та проблема, ради которой всё это и
делается.
"""

# Насколько сильно техника перестраивает соединение. Порядок задан явно:
# именно доминирующий режим определяет, чем стратегия будет побеждена.
#
# `split`/`split2`/`disorder` — устаревшие написания, которые v1 всё ещё
# принимает; Rust сводит их к multisplit/multidisorder (ir.rs:144-145), поэтому
# и здесь они обязаны давать ту же нишу.
TECHNIQUE_BY_MODE = {
    "fake": ("inject", 1), "fakeknown": ("inject", 1), "rst": ("inject", 1), "rstack": ("inject", 1),
    "ipfrag1": ("fragment", 2), "ipfrag2": ("fragment", 2), "hopbyhop": ("fragment", 2),
    "destopt": ("fragment", 2), "udplen": ("fragment", 2),
    "multisplit": ("segment", 3), "split": ("segment", 3), "split2": ("segment", 3),
    "multidisorder": ("segment", 3), "disorder": ("segment", 3), "tamper": ("segment", 3),
    "fakedsplit": ("decoy-segment", 4), "fakeddisorder": ("decoy-segment", 4),
    "hostfakesplit": ("relocate", 5), "syndata": ("relocate", 5), "synack": ("relocate", 5),
}

# Почему получатель игнорирует фейк: испорченный пакет отбрасывает стек или
# NIC, пакет вне окна отбрасывает TCP. Это разные классы DPI.
MALFORMED_FOOLING = {"badsum", "md5sig", "hopbyhop", "hopbyhop2"}
OUT_OF_ORDER_FOOLING = {"badseq", "ts", "datanoack"}


def classify_strategy_niche(args):
    """Возвращает (техника, дальность, отрицаемость)."""
    technique, severity = "other", 0
    fixed_ttl, has_auto = None, False
    malformed = out_of_order = False

    for arg in args or []:
        if not isinstance(arg, str):
            continue
        key, _, value = arg.partition("=")
        if key == "--dpi-desync":
            for token in value.split(","):
                found = TECHNIQUE_BY_MODE.get(token.strip().lower())
                if found and found[1] > severity:
                    technique, severity = found
        elif key == "--dpi-desync-ttl":
            try:
                fixed_ttl = int(value)
            except ValueError:
                pass
        elif key == "--dpi-desync-autottl":
            has_auto = True
        elif key == "--dpi-desync-fooling":
            for token in value.split(","):
                token = token.strip().lower()
                if token in MALFORMED_FOOLING:
                    malformed = True
                elif token in OUT_OF_ORDER_FOOLING:
                    out_of_order = True

    # autottl перекрывает фиксированный TTL: v1 применяет измеренное число
    # хопов, а фиксированное значение остаётся запасным, так что поведение на
    # конкретном соединении — адаптивное.
    if has_auto:
        reach = "adaptive"
    elif fixed_ttl is None:
        reach = "unbounded"
    elif fixed_ttl <= 4:
        reach = "short"
    elif fixed_ttl <= 8:
        reach = "medium"
    else:
        reach = "long"

    if malformed and out_of_order:
        deniability = "mixed"
    elif malformed:
        deniability = "malformed"
    elif out_of_order:
        deniability = "out-of-order"
    else:
        deniability = "ttl"

    return (technique, reach, deniability)
