#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fix_boot_crown.py -- SukiSU-Nova on polaris 4.9 (MIUI 11)

Run from the KERNEL TREE ROOT (after scripts/sukisu_patch.sh).

1. Adds a boot-time manager-crown fallback (workqueue retry, independent of
   init.rc injection and ksud post-fs-data).
2. Adds /data/local/tmp/ksu_dbg.log instrumentation so we can see, without
   root or pstore, whether init.rc injection / post-fs-data / fsnotify /
   setuid-fd delivery actually happen.
"""
import pathlib
import sys

ROOT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else '.')
K = ROOT / 'kernel' / 'kernelsu'


def patch(rel, old, new, count=1):
    p = K / rel
    s = p.read_text(encoding='utf-8')
    got = s.count(old)
    if got != count:
        raise SystemExit('anchor mismatch in %s: found %d, want %d\n---\n%s' % (rel, got, count, old[:400]))
    p.write_text(s.replace(old, new, count), encoding='utf-8')
    print('patched %s' % rel)


DBG = '''
/* ---------------- local debug + boot crown fallback --------------------- */
#include <linux/workqueue.h>

int ksu_dbg_rc_hit;
int ksu_dbg_pfd_hit;

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

# 1) debug helpers in the unity build master file
patch('ksu_main.c',
      '#include "kernel_includes.h"\n',
      '#include "kernel_includes.h"\n' + DBG)

# 2) start the crown work from kernelsu_init()
patch('ksu_main.c',
      '    ksu_feature_apply_forced();\n\n    ksu_extension_apply_forced();\n\n    return 0;\n}',
      '    ksu_feature_apply_forced();\n\n    ksu_extension_apply_forced();\n\n    ksu_crown_work_start();\n\n    return 0;\n}')

# 3) instrumentation inside on_post_fs_data()
patch('runtime/ksud.c',
      '''    ksu_load_allow_list();
    ksu_dynamic_manager_load();
    ksu_observer_init();''',
      '''    ksu_dbg_pfd_hit = 1;
    ksu_dbg("pfd_enter", 1);
    ksu_load_allow_list();
    ksu_dynamic_manager_load();
    ksu_observer_init();
    ksu_dbg("pfd_after_observer", ksu_is_manager_appid_valid());
    if (!ksu_is_manager_appid_valid())
        track_throne(false);
    ksu_dbg("pfd_after_crown_appid", (long)ksu_manager_appid);''')

# 4) crown worker right after on_post_fs_data()
CROWN = '''
static struct delayed_work ksu_crown_work;
static int ksu_crown_tries;

static void ksu_crown_work_fn(struct work_struct *work)
{
    if (ksu_is_manager_appid_valid()) {
        ksu_dbg("crown_work_already", (long)ksu_manager_appid);
        return;
    }
    ksu_crown_tries++;
    ksu_dbg("crown_work_try", ksu_crown_tries);
    track_throne(false);
    ksu_dbg("crown_work_rc_hit", ksu_dbg_rc_hit);
    ksu_dbg("crown_work_pfd_hit", ksu_dbg_pfd_hit);
    if (ksu_is_manager_appid_valid()) {
        ksu_dbg("crown_work_crowned", (long)ksu_manager_appid);
        return;
    }
    if (ksu_crown_tries < 40)
        schedule_delayed_work(&ksu_crown_work, 2 * HZ);
    else
        ksu_dbg("crown_work_give_up", ksu_crown_tries);
}

void ksu_crown_work_start(void)
{
    INIT_DELAYED_WORK(&ksu_crown_work, ksu_crown_work_fn);
    schedule_delayed_work(&ksu_crown_work, 4 * HZ);
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

# 5) prove whether the init.rc read hook fires
patch('runtime/ksud.c',
      '    pr_info("read init.rc, comm: %s, rc_count: %zu\\n", current->comm, ksu_rc_len);',
      '    pr_info("read init.rc, comm: %s, rc_count: %zu\\n", current->comm, ksu_rc_len);\n    ksu_dbg_rc_hit++;')

# 6) throne tracker logs
patch('manager/throne_tracker.c',
      '            pr_info("Crowning manager: uid=%d\\n", np->uid);',
      '            pr_info("Crowning manager: uid=%d\\n", np->uid);\n            ksu_dbg("crown_uid", np->uid);')

patch('manager/throne_tracker.c',
      '''void track_throne(bool prune_only)
{
    const struct cred *old_cred = override_creds(ksu_cred);''',
      '''void track_throne(bool prune_only)
{
    const struct cred *old_cred = override_creds(ksu_cred);
    ksu_dbg("track_throne_enter", prune_only);''')

patch('manager/throne_tracker.c',
      '        pr_err("%s: open " SYSTEM_PACKAGES_LIST_PATH " failed: %ld\\n", __func__, PTR_ERR(fp));',
      '        pr_err("%s: open " SYSTEM_PACKAGES_LIST_PATH " failed: %ld\\n", __func__, PTR_ERR(fp));\n        ksu_dbg("track_open_fail", PTR_ERR(fp));')

patch('manager/throne_tracker.c',
      '''prune:
    // then prune the allowlist''',
      '''prune:
    ksu_dbg("track_prune_appid", (long)ksu_manager_appid);
    // then prune the allowlist''')

# 7) fsnotify observer logs
patch('manager/pkg_observer.c',
      '''static KSU_DECL_FSNOTIFY_OPS(ksu_handle_generic_event)
{
    if (!file_name || (mask & FS_ISDIR))''',
      '''static KSU_DECL_FSNOTIFY_OPS(ksu_handle_generic_event)
{
    ksu_dbg("fsn_event", (long)mask);
    if (!file_name || (mask & FS_ISDIR))''')

patch('manager/pkg_observer.c',
      '''int ksu_observer_init(void)
{
    int ret = 0;''',
      '''int ksu_observer_init(void)
{
    int ret = 0;
    ksu_dbg("observer_init_enter", 0);''')

patch('manager/pkg_observer.c',
      '''    ret = watch_one_dir(&g_watch);''',
      '''    ret = watch_one_dir(&g_watch);
    ksu_dbg("observer_watch_ret", ret);''')

# 8) LSM setuid path logs
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
        ksu_dbg("setuid_manager_fd", new_uid);
        ksu_install_fd();
        return 0;
    }
    if (!ksu_is_manager_appid_valid() && is_appuid(new_uid)) {
        static int dbg_left = 4;
        if (dbg_left > 0) {
            dbg_left--;
            ksu_dbg("setuid_app_manager_invalid", new_uid);
        }
    }''')

print('fix_boot_crown.py: all patches applied')
