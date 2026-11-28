#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fix_boot_crown.py -- MINIMAL variant (build 3).

Root cause hypothesis: on this MIUI 11 image PMS never rewrites
/data/system/packages.list, so the only crown trigger (fsnotify on that file)
never fires; /data/system watch registration may also fail early.

Fix = crown from paths that are PROVEN to run and to have a mounted /data:
  1. on_post_fs_data()  (ksud process context, /data mounted)
  2. on_boot_completed() (switch track_throne(true) -> track_throne(false))

No workqueue, no timers, no file IO, no logging added anywhere.
"""
import pathlib
import sys

ROOT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else '.')
K = ROOT / 'kernel' / 'kernelsu'
NL = chr(10)


def patch(rel, old, new, count=1):
    p = K / rel
    s = p.read_text(encoding='utf-8')
    got = s.count(old)
    if got != count:
        raise SystemExit('anchor mismatch in %s: found %d want %d' % (rel, got, count) + NL + old[:400])
    p.write_text(s.replace(old, new, count), encoding='utf-8')
    print('patched ' + rel)


patch('runtime/ksud.c',
      '''    ksu_load_allow_list();
    ksu_dynamic_manager_load();
    ksu_observer_init();''',
      '''    ksu_load_allow_list();
    ksu_dynamic_manager_load();
    ksu_observer_init();
    // MIUI may never rewrite /data/system/packages.list, so the fsnotify
    // crown trigger never fires. Crown right here: /data is mounted and
    // this runs in the ksud process context.
    if (!ksu_is_manager_appid_valid())
        track_throne(false);''')

patch('runtime/ksud.c',
      '    track_throne(true);',
      '    track_throne(false);')

print('fix_boot_crown.py: minimal patches applied')
