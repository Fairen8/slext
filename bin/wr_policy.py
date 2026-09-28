#!/usr/bin/env python3
"""Политика авто-режима зала ожидания (чистые функции, без зависимостей).

Используется slext-api.py и тестами. Никаких обращений к сети/файлам/БД.
"""


def clamp_int(v, lo, hi, default):
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return default


def wr_auto_decision(au, st, actual, rate, now):
    """Решение авто-режима.

    au   — настройки авто-режима (threshold/off_threshold/window/hold/hold_off/cooldown/min_off)
    st   — предыдущее состояние: above, below, manual_at, changed_at, source
    actual — текущее фактическое состояние зала
    rate — реальный трафик, запросов/мин
    now  — текущее время (unix)

    Возвращает (desired|None, action, reason, counters):
    desired — что сделать (True/False) или None, если менять не нужно;
    action  — 'on' | 'off' | 'wait';
    reason  — человекочитаемая причина;
    counters — новое состояние счётчиков (above/below/rate/last_eval/...).
    """
    thr = clamp_int(au.get('threshold'), 1, 10 ** 6, 60)
    off = clamp_int(au.get('off_threshold'), 0, thr, min(20, thr))
    hold = clamp_int(au.get('hold'), 1, 20, 3)
    hold_off = clamp_int(au.get('hold_off'), 1, 60, 4)
    cool = clamp_int(au.get('cooldown'), 30, 86400, 600)
    min_off = clamp_int(au.get('min_off'), 0, 86400, 600)
    above = int(st.get('above') or 0)
    below = int(st.get('below') or 0)
    above = above + 1 if rate >= thr else 0
    below = below + 1 if rate <= off else 0
    desired, action = None, 'wait'
    reason = 'трафик %s зап/мин, порог вкл %s — %s/%s проверок подряд' % (rate, thr, above, hold)
    if not actual:
        if above >= hold and now - int(st.get('manual_at') or 0) >= min_off:
            desired, action = True, 'on'
            reason = 'трафик %s зап/мин ≥ %s — %s проверок подряд' % (rate, thr, above)
    elif st.get('source') == 'auto':
        if below >= hold_off and now - int(st.get('changed_at') or 0) >= cool:
            desired, action = False, 'off'
            reason = 'трафик %s зап/мин ≤ %s — %s проверок подряд' % (rate, off, below)
    if action != 'wait':
        above = below = 0
    counters = {'above': above, 'below': below, 'rate': rate, 'last_eval': int(now),
                'window': clamp_int(au.get('window'), 30, 3600, 60), 'threshold': thr,
                'off_threshold': off}
    return desired, action, reason, counters
