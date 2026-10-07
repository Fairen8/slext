#!/usr/bin/env python3
"""Юнит-тесты политики авто-режима зала ожидания (bin/wr_policy.py)."""
import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location('wr_policy', os.path.join(ROOT, 'bin', 'wr_policy.py'))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

FAIL = 0
NOW = 1000000
AU = {'threshold': 60, 'off_threshold': 20, 'window': 60, 'hold': 3, 'hold_off': 4,
      'cooldown': 600, 'min_off': 600}


def check(name, cond):
    global FAIL
    print(('OK  ' if cond else 'FAIL') + ' ' + name)
    if not cond:
        FAIL += 1


st = {'above': 0, 'below': 0, 'manual_at': NOW - 700, 'source': 'manual'}
des, act, reason, cnt = mod.wr_auto_decision(AU, st, False, 100, NOW)
check('1a один замер выше порога — не включаем', des is None and cnt['above'] == 1 and act == 'wait')
des, act, reason, cnt = mod.wr_auto_decision(AU, cnt, False, 100, NOW + 20)
check('1b два замера — не включаем', des is None and cnt['above'] == 2)
des, act, reason, cnt = mod.wr_auto_decision(AU, cnt, False, 100, NOW + 40)
check('1c три замера подряд — включаем', des is True and act == 'on' and cnt['above'] == 0)

cnt2 = {'above': 2, 'below': 0}
des, act, reason, cnt2 = mod.wr_auto_decision(AU, cnt2, False, 10, NOW)
check('2 трафик ниже порога сбрасывает счётчик', des is None and cnt2['above'] == 0)

st3 = {'above': 5, 'below': 0, 'manual_at': NOW - 100, 'source': 'manual'}
des, act, reason, cnt3 = mod.wr_auto_decision(AU, st3, False, 100, NOW)
check('3 ручное выключение блокирует авто (min_off)', des is None)

st4 = {'above': 0, 'below': 3, 'changed_at': NOW - 700, 'source': 'auto'}
des, act, reason, cnt4 = mod.wr_auto_decision(AU, st4, True, 5, NOW)
check('4a авто выключает зал после hold_off и cooldown', des is False and act == 'off' and cnt4['below'] == 0)

st5 = {'above': 0, 'below': 9, 'changed_at': NOW - 700, 'source': 'manual'}
des, act, reason, cnt5 = mod.wr_auto_decision(AU, st5, True, 5, NOW)
check('4b зал, включённый вручную, авто не выключает', des is None)

st6 = {'above': 0, 'below': 9, 'changed_at': NOW - 100, 'source': 'auto'}
des, act, reason, cnt6 = mod.wr_auto_decision(AU, st6, True, 5, NOW)
check('5 cooldown не даёт выключить сразу', des is None and cnt6['below'] >= 4)

AU2 = dict(AU, threshold=50, off_threshold=100)
des, act, reason, cnt7 = mod.wr_auto_decision(AU2, {'above': 0, 'below': 0}, False, 60, NOW)
check('6 off_threshold ограничен порогом включения', cnt7['off_threshold'] == 50)

des, act, reason, cnt8 = mod.wr_auto_decision(AU, {'above': 0, 'below': 0}, False, 60, NOW)
check('7 трафик ровно на пороге считается «выше»', cnt8['above'] == 1)
des, act, reason, cnt9 = mod.wr_auto_decision(AU, {'above': 0, 'below': 0}, True, 20, NOW)
check('8 трафик ровно на пороге выключения считается «ниже»', cnt9['below'] == 1)

# API-маршруты (whitelist + rate-limit)
paths = mod.api_norm_paths(['/api/v1/', ' api/v2 ', '/../etc', '/a b', '/api/v1/', '/api/v2'])
check('9 api_norm_paths: фильтрация и дедуп', paths == ['/api/v1/', '/api/v2'])
check('10 api_zone_name: санитизация', mod.api_zone_name('app.example.com') == 'slext_api_app_example_com')
check('11 api_zone_name: пустой хост', mod.api_zone_name('') == 'slext_api_site')
check('12 api_rl_paths_re: якорь', mod.api_rl_paths_re(['/api/v1/']) == '~^(/api/v1/)')
check('13 api_rl_paths_re: без путей', mod.api_rl_paths_re([]) == '^$')

print('FAIL=%d' % FAIL)
sys.exit(1 if FAIL else 0)
