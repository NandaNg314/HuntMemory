# companion_kpm: KernelPatch (APatch) 硬件断点内核伴侣模块

这是针对 APatch (KernelPatch) 架构编译的伴侣内核模块（`hm_hwbp.kpm`），用于为 `hmkpm-mcp` 提供内核层硬件断点/数据观察点拦截支持，达到对目标进程 100% 幽灵级隐藏（`TracerPid == 0`，不投递用户态信号）。

---

## 1. 构建环境与命令

基于 Android NDK Clang 编译器与 KernelPatch 内核头文件构建：

* **NDK 路径**：`D:/AndroidSdk/ndk/30.0.14904198` (Clang aarch64-linux-android31)
* **KernelPatch 源码路径**：`D:/ai/KernelPatch`

### 编译步骤
```bash
cd companion_kpm
make clean
make
```

---

## 2. KernelPatch KPM 编译与加载避坑指南（关键记忆）

在 APatch 管理器中加载 `.kpm` 文件时，若报 **`-1` 失败**，99% 是由于 ELF 重定位溢出或未遵守 ABI 引起。

### 踩坑一：`overflow in relocation type 261`（严重）
* **现象**：`dmesg` 报错：
  ```text
  [+] KP D     .rodata.cst32 ffffffeee9a0aba8 20
  [+] KP D     .eh_frame ffffffeee9a0abc8 98
  [+] KP D     .symtab ffffffeee9a109c8 348
  overflow in relocation type 261 val ffffffeee9a099c8
  ```
* **原因**：Relocation type 261 是 ARM64 的 `R_AARCH64_PREL32`（32 位 PC 相对寻址重定位）。Clang 默认会生成 `.eh_frame` 异常展开段；当 KernelPatch 将模块加载到 64 位高地址内核空间时，32 位相对寻址越界溢出。
* **解决办法**：
  1. `CFLAGS` 必须加上：
     `-fno-asynchronous-unwind-tables -fno-unwind-tables -fno-PIC -fvisibility=hidden`
  2. 链接后必须使用 `llvm-strip` 彻底清除展开段：
     `llvm-strip -g --strip-unneeded --strip-debug --remove-section=.comment --remove-section=.note.GNU-stack --remove-section=.eh_frame hm_hwbp.kpm`

### 踩坑二：未重定向 PLT 段
* **解决办法**：必须配合链接脚本 `hm_hwbp.lds`，将无用段设置为 `(NOLOAD)`：
  ```lds
  SECTIONS {
      .plt (NOLOAD) : { BYTE(0) }
      .init.plt (NOLOAD) : { BYTE(0) }
      .text.ftrace_trampoline (NOLOAD) : { BYTE(0) }
  }
  ```

### 踩坑三：KernelPatch 官方 ABI 规范
* **模块元数据与入口**：必须使用 `<kpmodule.h>` 官方宏：
  ```c
  KPM_NAME("hm_hwbp");
  KPM_VERSION("1.0.0");
  KPM_LICENSE("GPL v2");
  KPM_AUTHOR("hmkpm-mcp");
  KPM_DESCRIPTION("KernelPatch Hardware Breakpoint Module");

  KPM_INIT(module_init_handler);
  KPM_CTL0(module_control_handler);
  KPM_EXIT(module_cleanup_handler);
  ```
* **Syscall Hook 回调签名**：
  必须是 `void hook_func(hook_fargs3_t *args, void *udata)`，通过 `syscall_argn(args, 0)` 取参，通过 `args->skip_origin = 1; args->ret = ...;` 短路原始系统调用。
