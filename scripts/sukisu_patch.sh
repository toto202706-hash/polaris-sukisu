#!/usr/bin/env bash
# Integrate SukiSU-Nova (builtin branch) into the polaris MIUI kernel tree.
# Usage: bash scripts/sukisu_patch.sh /abs/path/to/cloned/sukisu   (run from kernel tree root)
set -euo pipefail

SUKISU="$1"
if [ -z "$SUKISU" ]; then echo "usage: sukisu_patch.sh <sukisu-repo-dir>"; exit 2; fi
[ -d "$SUKISU/kernel" ] || { echo "no kernel dir in $SUKISU"; exit 2; }
[ -f fs/read_write.c ] && [ -f fs/stat.c ] || { echo "not a kernel tree root"; exit 2; }

echo "== 1. drop KernelSU-Next driver"
rm -rf kernel/kernelsu

echo "== 2. install SukiSU-Nova builtin driver"
cp -a "$SUKISU/kernel" kernel/kernelsu
ls kernel/kernelsu/ksu_main.c >/dev/null

echo "== 3. add CONFIG_KSU_MANUAL_HOOK compatibility symbol"
if ! grep -q '^config KSU_MANUAL_HOOK' kernel/kernelsu/Kconfig; then
cat >> kernel/kernelsu/Kconfig <<'KEOF'

config KSU_MANUAL_HOOK
	bool "Manual hook compatibility symbol"
	depends on KSU
	default y
	help
	  The polaris tree carries manual hook call sites guarded by this
	  symbol (KernelSU-Next ABI). Keep it enabled so those sites compile.
KEOF
fi

echo "== 4. fs/read_write.c : sys_read hook signature"
python3 - <<'PY'
import pathlib
p = pathlib.Path('fs/read_write.c')
s = p.read_text(encoding='utf-8')
old_decl = 'extern void ksu_handle_sys_read(unsigned int fd);'
new_decl = 'extern int ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr, size_t *count_ptr);'
assert s.count(old_decl) == 1, 'read_write decl not found/unique'
s = s.replace(old_decl, new_decl)
old_call = 'ksu_handle_sys_read(fd);'
assert s.count(old_call) == 1, 'read_write call not found/unique'
s = s.replace(old_call, 'ksu_handle_sys_read(fd, &buf, &count);')
p.write_text(s, encoding='utf-8')
print('read_write.c patched')
PY

echo "== 5. fs/stat.c : drop fstat-return hooks, add vfs_fstat hook"
python3 - <<'PY'
import pathlib
p = pathlib.Path('fs/stat.c')
s = p.read_text(encoding='utf-8')

block = """#ifdef CONFIG_KSU_MANUAL_HOOK
extern int ksu_handle_stat(int *dfd, const char __user **filename, int *flags);
extern void ksu_handle_newfstat_ret(unsigned int *fd, struct stat __user **statbuf);
#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
extern void ksu_handle_fstat64_ret(unsigned long *fd, struct stat64 __user **statbuf);
#endif
#endif"""
newblock = """#ifdef CONFIG_KSU_MANUAL_HOOK
extern int ksu_handle_stat(int *dfd, const char __user **filename, int *flags);
extern void ksu_handle_vfs_fstat(int fd, loff_t *kstat_size_ptr);
#endif"""
assert s.count(block) == 1, 'stat decl block not found'
s = s.replace(block, newblock)

b1 = "#ifdef CONFIG_KSU_MANUAL_HOOK\n\tif (!error)\n\t\tksu_handle_newfstat_ret(&fd, &statbuf);\n#endif\n"
b2 = "#ifdef CONFIG_KSU_MANUAL_HOOK\n\tif (!error)\n\t\tksu_handle_fstat64_ret(&fd, &statbuf);\n#endif\n"
for b, name in ((b1, 'newfstat'), (b2, 'fstat64')):
    assert s.count(b) == 1, name + ' block not found'
    s = s.replace(b, '')

vf_old = "\tif (f.file) {\n\t\terror = vfs_getattr(&f.file->f_path, stat);\n\t\tfdput(f);\n\t}"
vf_new = "\tif (f.file) {\n\t\terror = vfs_getattr(&f.file->f_path, stat);\n#ifdef CONFIG_KSU_MANUAL_HOOK\n\t\tksu_handle_vfs_fstat(fd, &stat->size);\n#endif\n\t\tfdput(f);\n\t}"
assert s.count(vf_old) == 1, 'vfs_fstat body not found'
s = s.replace(vf_old, vf_new)

assert 'ksu_handle_newfstat_ret' not in s
assert 'ksu_handle_fstat64_ret' not in s
assert 'ksu_handle_vfs_fstat(fd' in s
p.write_text(s, encoding='utf-8')
print('stat.c patched')
PY

echo "== 6. sanity: hook sites"
grep -n "ksu_handle_" fs/exec.c fs/open.c fs/stat.c fs/read_write.c kernel/reboot.c drivers/input/input.c | sed "s/^/   /"
echo "== DONE"
