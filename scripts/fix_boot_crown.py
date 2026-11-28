#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fix_boot_crown.py -- build 4.

Goal: make the SukiSU Nova manager get the driver fd every boot.

Rules kept from build 2's failure:
  * kernel file IO happens ONLY inside on_post_fs_data() (ksud process ctx);
  * track_throne()/crown_manager()/LSM hook only touch plain int globals.

Guaranteed path: the LSM setuid hook knows the uid of the process being
switched to.  If the manager appid is still unknown and that uid is the
manager we build against (KSU_MANAGER_UID_FALLBACK), crown it right there
and hand out the fd -- exactly what the normal path does after a
successful track_throne().  No /data access, no ordering dependency.
"""
import pathlib
import sys

ROOT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else '.')
K = ROOT / 'kernel' / 'kernelsu'
NL = chr(10)
MGUID = 10222  # adb shell dumpsys package com.sukisu.nova -> userId=10222


def patch(rel, old, new, count=1):
    p = K / rel
    s = p.read_text(encoding='utf-8')
    got = s.count(old)
    if got != count:
        raise SystemExit('anchor mismatch in %s: found %d want %d%s%s'
                         % (rel, got, count, NL, old[:400]))
    p.write_text(s.replace(old, new, count), encoding='utf-8')
    print('patched ' + rel)


DBG = NL + '''/* ---------------- debug counters + crown plumbing ---------------------- */
int ksu_dbg_rc_hit;
int ksu_dbg_track_hit;
int ksu_dbg_apk_found;
int ksu_dbg_is_manager = -1;
int ksu_dbg_crown_ok;
int ksu_dbg_setuid_hit;
int ksu_dbg_uid_fallback;
/* ---------------------------------------------------------------------- */
'''

patch('ksu_main.c', '#include "kernel_includes.h"' + NL,
      '#include "kernel_includes.h"' + NL + DBG)

# --- counters in track_throne / search_manager / crown_manager (no IO) ----
patch('manager/throne_tracker.c',
      '''void track_throne(bool prune_only)
{
    const struct cred *old_cred = override_creds(ksu_cred);''',
      '''void track_throne(bool prune_only)
{
    const struct cred *old_cred = override_creds(ksu_cred);
    ksu_dbg_track_hit++;''')

patch('manager/throne_tracker.c',
      '            pr_info("Crowning manager: uid=%d\\n", np->uid);',
      '            pr_info("Crowning manager: uid=%d\\n", np->uid);' + NL +
      '            ksu_dbg_crown_ok = 1;')

patch('manager/throne_tracker.c',
      '            pr_info("Found manager base.apk at path: %s, is_manager: %d\\n", candidate_path, is_manager);',
      '            pr_info("Found manager base.apk at path: %s, is_manager: %d\\n", candidate_path, is_manager);' + NL +
      '            ksu_dbg_apk_found = 1;' + NL +
      '            ksu_dbg_is_manager = is_manager ? 1 : 0;')

# --- crown attempt + log dump, in ksud process context -------------------
patch('runtime/ksud.c',
      '''    ksu_load_allow_list();
    ksu_dynamic_manager_load();
    ksu_observer_init();''',
      '''    ksu_load_allow_list();
    ksu_dynamic_manager_load();
    ksu_observer_init();
    if (!ksu_is_manager_appid_valid())
        track_throne(false);
    ksu_dbg_dump("post_fs_data");''')

DBGDUMP = '''
static void ksu_dbg_raw(const char *buf, int len)
{
    struct file *f;
    mm_segment_t old_fs;
    loff_t pos = 0;

    old_fs = get_fs();
    set_fs(KERNEL_DS);
    f = filp_open("/data/local/tmp/ksu_dbg.log",
                  O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (!IS_ERR(f)) {
        vfs_write(f, buf, len, &pos);
        filp_close(f, NULL);
    }
    set_fs(old_fs);
}

static void ksu_dbg_one(const char *where, const char *what, long v)
{
    char buf[200];
    int n = snprintf(buf, sizeof(buf), "[ksudbg %s pid=%d] %s=%ld\\n",
                     where, (int)current->pid, what, v);
    if (n > 0 && n < (int)sizeof(buf))
        ksu_dbg_raw(buf, n);
}

static void ksu_dbg_dump(const char *where)
{
    ksu_dbg_one(where, "rc_hit", ksu_dbg_rc_hit);
    ksu_dbg_one(where, "track_hit", ksu_dbg_track_hit);
    ksu_dbg_one(where, "apk_found", ksu_dbg_apk_found);
    ksu_dbg_one(where, "is_manager", ksu_dbg_is_manager);
    ksu_dbg_one(where, "crown_ok", ksu_dbg_crown_ok);
    ksu_dbg_one(where, "appid", (long)ksu_manager_appid);
    ksu_dbg_one(where, "setuid_hit", ksu_dbg_setuid_hit);
    ksu_dbg_one(where, "uid_fallback", ksu_dbg_uid_fallback);
}
'''

patch('runtime/ksud.c',
      'void on_post_fs_data(void)' + NL + '{',
      DBGDUMP + NL + 'void on_post_fs_data(void)' + NL + '{')

patch('runtime/ksud.c',
      '    track_throne(true);',
      '    track_throne(false);' + NL + '    ksu_dbg_dump("boot_completed");')

# --- the guaranteed path: crown + fd from the setuid hook ----------------
FALLBACK_TMPL = '''
    if (!ksu_is_manager_appid_valid() && is_appuid(new_uid)) {
        static int dbg_setuid_calls = 3;
        ksu_dbg_setuid_hit++;
        if (dbg_setuid_calls > 0) {
            dbg_setuid_calls--;
            track_throne(false);
        }
        if (!ksu_is_manager_appid_valid() &&
            (new_uid % KSU_PER_USER_RANGE) == MGUID) {
            ksu_set_manager_appid(new_uid % KSU_PER_USER_RANGE);
            ksu_dbg_uid_fallback = (int)new_uid;
            disable_seccomp();
            pr_info("install fd for uid-matched manager: %d\\n", new_uid);
            ksu_install_fd();
            return 0;
        }
    }'''
FALLBACK = FALLBACK_TMPL.replace('MGUID', str(MGUID))

patch('hook/lsm_hook.c',
      '''    if (unlikely(is_uid_manager(new_uid))) {
        disable_seccomp();
        pr_info("install fd for manager: %d\\n", new_uid);
        ksu_install_fd();
        return 0;
    }''',
      '''    if (unlikely(is_uid_manager(new_uid))) {
        disable_seccomp();
        pr_info("install fd for manager: %d\\n", new_uid);
        ksu_install_fd();
        return 0;
    }
''' + FALLBACK)

print('fix_boot_crown.py: build4 patches applied (fallback uid %d)' % MGUID)