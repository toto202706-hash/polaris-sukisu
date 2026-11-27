#!/usr/bin/env python3
"""
Inject SukiSU/KernelSU syscall hooks into a Linux 4.9 (Xiaomi polaris-o-oss) tree.
Idempotent: files already containing a marker are left alone.
Usage: python3 patch_ksu49.py <kernel_source_dir>
"""
import os, sys, io

MARK = "KSU_HOOK_INJECTED"

def read(p):
    with io.open(p, "r", encoding="utf-8", errors="surrogateescape") as f:
        return f.read()

def write(p, s):
    with io.open(p, "w", encoding="utf-8", errors="surrogateescape", newline="") as f:
        f.write(s)

def once(text, anchor, payload, where="after", start=0, what=""):
    """Insert payload once relative to first occurrence of anchor at/after start."""
    i = text.find(anchor, start)
    if i < 0:
        raise SystemExit("ANCHOR_NOT_FOUND [%s]: %r" % (what, anchor[:60]))
    if payload.strip() in text:
        return text
    j = i if where == "before" else i + len(anchor)
    return text[:j] + payload + text[j:]

BLOCK_IF = "#ifdef CONFIG_KSU\n%s#endif\n"

def patch_read_write(root):
    p = os.path.join(root, "fs/read_write.c")
    t = read(p)
    if MARK in t:
        print("skip fs/read_write.c (already patched)"); return
    decl = (
        "\n#ifdef CONFIG_KSU\n"
        "extern bool ksu_vfs_read_hook __read_mostly;\n"
        "extern int ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr,\n"
        "\t\t\tsize_t *count_ptr);\n"
        "#endif\n\n"
    )
    t = once(t, "static inline void file_pos_write(struct file *file, loff_t pos)\n{\n\tfile->f_pos = pos;\n}\n",
             decl, "after", what="read_write decl")
    i = t.find("SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)")
    if i < 0:
        raise SystemExit("ANCHOR_NOT_FOUND: SYSCALL_DEFINE3(read")
    hook = (
        "\t\t#ifdef CONFIG_KSU\n"
        "\t\tif (unlikely(ksu_vfs_read_hook))\n"
        "\t\t\tksu_handle_sys_read(fd, &buf, &count);\n"
        "\t\t#endif\n"
    )
    anchor = "\t\tloff_t pos = file_pos_read(f.file);\n"
    j = t.find(anchor, i)
    if j < 0:
        raise SystemExit("ANCHOR_NOT_FOUND: read body")
    t = t[:j + len(anchor)] + hook + t[j + len(anchor):]
    t += "\n/* %s fs/read_write.c */\n" % MARK
    write(p, t)
    print("patched fs/read_write.c")

def patch_stat(root):
    p = os.path.join(root, "fs/stat.c")
    t = read(p)
    if MARK in t:
        print("skip fs/stat.c (already patched)"); return
    decl = BLOCK_IF % ("extern int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags);\n")
    t = once(t, "#if !defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_SYS_NEWFSTATAT)\n",
             decl + "\n", "before", what="stat decl")
    hook = (
        "\t#ifdef CONFIG_KSU\n"
        "\tksu_handle_stat(&dfd, &filename, &flag);\n"
        "\t#endif\n"
    )
    for sig in ("SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,",
                "SYSCALL_DEFINE4(fstatat64, int, dfd, const char __user *, filename,"):
        i = t.find(sig)
        if i < 0:
            raise SystemExit("ANCHOR_NOT_FOUND: %s" % sig)
        anchor = "\tstruct kstat stat;\n\tint error;\n"
        j = t.find(anchor, i)
        if j < 0:
            raise SystemExit("ANCHOR_NOT_FOUND: body of %s" % sig)
        t = t[:j + len(anchor)] + "\n" + hook + t[j + len(anchor):]
    t += "\n/* %s fs/stat.c */\n" % MARK
    write(p, t)
    print("patched fs/stat.c")

def patch_open(root):
    p = os.path.join(root, "fs/open.c")
    t = read(p)
    if MARK in t:
        print("skip fs/open.c (already patched)"); return
    decl = BLOCK_IF % ("extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode,\n"
                       "\t\t\t\tint *flags);\n")
    t = once(t, "SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)\n",
             decl, "before", what="open decl")
    i = t.find("SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)")
    anchor = "\tunsigned int lookup_flags = LOOKUP_FOLLOW;\n"
    j = t.find(anchor, i)
    if j < 0:
        raise SystemExit("ANCHOR_NOT_FOUND: faccessat body")
    hook = (
        "\n\t#ifdef CONFIG_KSU\n"
        "\tksu_handle_faccessat(&dfd, &filename, &mode, NULL);\n"
        "\t#endif\n"
    )
    t = t[:j + len(anchor)] + hook + t[j + len(anchor):]
    t += "\n/* %s fs/open.c */\n" % MARK
    write(p, t)
    print("patched fs/open.c")

def patch_exec(root):
    p = os.path.join(root, "fs/exec.c")
    t = read(p)
    if MARK in t:
        print("skip fs/exec.c (already patched)"); return
    decl = BLOCK_IF % (
        "extern bool ksu_execveat_hook __read_mostly;\n"
        "extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,\n"
        "\t\t\tvoid *envp, int *flags);\n"
        "extern int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr, void *argv,\n"
        "\t\t\tvoid *envp, int *flags);\n"
    )
    t = once(t, "/*\n * sys_execve() executes a new program.\n */\n", decl + "\n", "after", what="exec decl")
    hook_native = (
        "\t#ifdef CONFIG_KSU\n"
        "\tif (unlikely(ksu_execveat_hook))\n"
        "\t\tksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);\n"
        "\telse\n"
        "\t\tksu_handle_execveat_sucompat((int *)AT_FDCWD, &filename, NULL, NULL, NULL);\n"
        "\t#endif\n"
    )
    i = t.find("int do_execve(struct filename *filename,")
    if i < 0:
        raise SystemExit("ANCHOR_NOT_FOUND: do_execve")
    anchor = "\tstruct user_arg_ptr envp = { .ptr.native = __envp };\n"
    j = t.find(anchor, i)
    if j < 0:
        raise SystemExit("ANCHOR_NOT_FOUND: do_execve body")
    t = t[:j + len(anchor)] + hook_native + t[j + len(anchor):]

    hook_compat = (
        "\t#ifdef CONFIG_KSU\n"
        "\tif (!ksu_execveat_hook)\n"
        "\t\tksu_handle_execveat_sucompat((int *)AT_FDCWD, &filename, NULL, NULL, NULL); /* 32-bit su */\n"
        "\t#endif\n"
    )
    i = t.find("static int compat_do_execve(struct filename *filename,")
    if i < 0:
        raise SystemExit("ANCHOR_NOT_FOUND: compat_do_execve")
    anchor = "\t\t.ptr.compat = __envp,\n\t};\n"
    j = t.find(anchor, i)
    if j < 0:
        raise SystemExit("ANCHOR_NOT_FOUND: compat_do_execve body")
    t = t[:j + len(anchor)] + hook_compat + t[j + len(anchor):]
    t += "\n/* %s fs/exec.c */\n" % MARK
    write(p, t)
    print("patched fs/exec.c")

def patch_input(root):
    p = os.path.join(root, "drivers/input/input.c")
    t = read(p)
    if MARK in t:
        print("skip drivers/input/input.c (already patched)"); return
    decl = BLOCK_IF % (
        "extern bool ksu_input_hook __read_mostly;\n"
        "extern int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code, int *value);\n"
    )
    t = once(t, "void input_event(struct input_dev *dev,\n", decl, "before", what="input decl")
    i = t.find("void input_event(struct input_dev *dev,")
    anchor = "\tunsigned long flags;\n"
    j = t.find(anchor, i)
    if j < 0:
        raise SystemExit("ANCHOR_NOT_FOUND: input_event body")
    hook = (
        "\n\t#ifdef CONFIG_KSU\n"
        "\tif (unlikely(ksu_input_hook))\n"
        "\t\tksu_handle_input_handle_event(&type, &code, &value);\n"
        "\t#endif\n"
    )
    t = t[:j + len(anchor)] + hook + t[j + len(anchor):]
    t += "\n/* %s drivers/input/input.c */\n" % MARK
    write(p, t)
    print("patched drivers/input/input.c")

def patch_pty(root):
    p = os.path.join(root, "drivers/tty/pty.c")
    t = read(p)
    if MARK in t:
        print("skip drivers/tty/pty.c (already patched)"); return
    decl = BLOCK_IF % ("extern int ksu_handle_devpts(struct inode *inode);\n")
    t = once(t, "static struct tty_struct *pts_unix98_lookup(struct tty_driver *driver,\n",
             decl, "before", what="pty decl")
    i = t.find("static struct tty_struct *pts_unix98_lookup(struct tty_driver *driver,\n")
    anchor = "\tstruct tty_struct *tty;\n"
    j = t.find(anchor, i)
    if j < 0:
        raise SystemExit("ANCHOR_NOT_FOUND: pts_unix98_lookup body")
    hook = (
        "\tstruct inode *pts_inode;\n"
        "\n\t#ifdef CONFIG_KSU\n"
        "\tpts_inode = file->f_path.dentry->d_inode;\n"
        "\tksu_handle_devpts(pts_inode);\n"
        "\t#endif\n"
    )
    t = t[:j + len(anchor)] + hook + t[j + len(anchor):]
    t += "\n/* %s drivers/tty/pty.c */\n" % MARK
    write(p, t)
    print("patched drivers/tty/pty.c")

def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    patch_read_write(root)
    patch_stat(root)
    patch_open(root)
    patch_exec(root)
    patch_input(root)
    patch_pty(root)
    print("ALL_HOOKS_INJECTED")

main()
