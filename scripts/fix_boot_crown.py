#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fix_boot_crown.py -- SAFE variant.

Manager-crown fallback for SukiSU-Nova builtin on polaris 4.9 (MIUI 11).

Design rules (learned from the previous boot-looped build):
  * NO kernel file IO anywhere except inside the dedicated workqueue worker.
  * NO logging from LSM hooks, fsnotify callbacks, task_work or init.rc read.
    Those paths only bump plain int counters.
  * The worker waits 30s (so /data is mounted), requires system_state ==
    SYSTEM_RUNNING and a successful kern_path("/data/system") before it
    touches creds or files.
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


DBG = NL + '''/* ---------------- local debug + boot crown fallback --------------------- */
#include <linux/workqueue.h>

int ksu_dbg_rc_hit;
int ksu_dbg_pfd_hit;
int ksu_dbg_obs_ret = -1;

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

static void ksu_dbg(const char *what, long v)
{
    char buf[160];
    int n = snprintf(buf, sizeof(buf), "[ksudbg pid=%d uid=%d] %s=%ld\\n",
                     (int)current->pid, (int)current_uid().val, what, v);
    if (n > 0 && n < (int)sizeof(buf))
        ksu_dbg_raw(buf, n);
}
/* ----------------------------------------------------------------------- */
'''

patch('ksu_main.c', '#include "kernel_includes.h"' + NL,
      '#include "kernel_includes.h"' + NL + DBG)

patch('ksu_main.c',
      '    ksu_feature_apply_forced();' + NL + NL + '    ksu_extension_apply_forced();' + NL + NL + '    return 0;' + NL + '}',
      '    ksu_feature_apply_forced();' + NL + NL + '    ksu_extension_apply_forced();' + NL + NL +
      '    ksu_crown_work_start();' + NL + NL + '    return 0;' + NL + '}')

patch('runtime/ksud.c',
      '''    ksu_load_allow_list();
    ksu_dynamic_manager_load();
    ksu_observer_init();''',
      '''    ksu_dbg_pfd_hit = 1;
    ksu_load_allow_list();
    ksu_dynamic_manager_load();
    ksu_observer_init();
    if (!ksu_is_manager_appid_valid())
        track_throne(false);''')

CROWN = '''
static struct delayed_work ksu_crown_work;
static int ksu_crown_tries;

static void ksu_crown_work_fn(struct work_struct *work)
{
    struct path root_path;
    int have_path;

    if (ksu_is_manager_appid_valid()) {
        ksu_dbg("crown_already", (long)ksu_manager_appid);
        return;
    }
    if (system_state != SYSTEM_RUNNING) {
        if (ksu_crown_tries < 60) {
            ksu_crown_tries++;
            schedule_delayed_work(&ksu_crown_work, 5 * HZ);
        }
        return;
    }
    have_path = kern_path("/data/system", 0, &root_path);
    if (have_path == 0)
        path_put(&root_path);
    if (have_path != 0) {
        if (ksu_crown_tries < 60) {
            ksu_crown_tries++;
            schedule_delayed_work(&ksu_crown_work, 5 * HZ);
        }
        return;
    }

    ksu_crown_tries++;
    ksu_dbg("crown_try", ksu_crown_tries);
    ksu_dbg("crown_rc_hit", ksu_dbg_rc_hit);
    ksu_dbg("crown_pfd_hit", ksu_dbg_pfd_hit);
    ksu_dbg("crown_obs_ret", ksu_dbg_obs_ret);
    track_throne(false);
    if (ksu_is_manager_appid_valid()) {
        ksu_dbg("crown_ok", (long)ksu_manager_appid);
        return;
    }
    ksu_dbg("crown_fail", (long)ksu_manager_appid);
    if (ksu_crown_tries < 20)
        schedule_delayed_work(&ksu_crown_work, 5 * HZ);
    else
        ksu_dbg("crown_give_up", ksu_crown_tries);
}

void ksu_crown_work_start(void)
{
    INIT_DELAYED_WORK(&ksu_crown_work, ksu_crown_work_fn);
    schedule_delayed_work(&ksu_crown_work, 30 * HZ);
}
'''

patch('runtime/ksud.c',
      '''    // retry forced features which failed at second stage
    ksu_feature_apply_forced();
    ksu_extension_apply_forced();
}''',
      '''    // retry forced features which failed at second stage
    ksu_feature_apply_forced();
    ksu_extension_apply_forced();
}
''' + CROWN)

patch('runtime/ksud.c',
      '    pr_info("read init.rc, comm: %s, rc_count: %zu\\n", current->comm, ksu_rc_len);',
      '    pr_info("read init.rc, comm: %s, rc_count: %zu\\n", current->comm, ksu_rc_len);' + NL + '    ksu_dbg_rc_hit++;')

patch('manager/pkg_observer.c',
      '    ret = watch_one_dir(&g_watch);',
      '    ret = watch_one_dir(&g_watch);' + NL + '    ksu_dbg_obs_ret = ret;')

print('fix_boot_crown.py: safe patches applied')
