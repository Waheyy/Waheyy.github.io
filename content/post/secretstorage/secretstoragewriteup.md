+++
date = '2025-10-26T21:39:54+08:00'
draft = true
title = 'AYCEP2025 verysecretstorage Modprobe Path overwrite'
categories = ["writeup"]
tags = ["kernel", "pwn"]
+++

#### Introduction:

WHATS'S UP GUYS! Welcome back to another text based youtube video. Today we will be reading a writeup about [verysecretstorage](https://github.com/KaligulaArmblessed/CTF-Challenges/tree/main/AYCEP_2024/verysecretstorage), a challenge made by [Kaligula](https://kaligulaarmblessed.github.io/) for AYCEP2024 (yes I am a year late and missed out greatly). This was my first kernel heap challenge as well as my first real kernel challenge and it was pretty fun. 

#### Table of Contents:

1. Protections
1. Binary analysis
1. Exploit

#### Protections:

Since this is my first kpwn challenge I will be going through the common protections as well as the ones that people do not talk about often in beginner writeups (in my exp pls no sue me).

As usual, protections help narrow down the options so we have:

1. **SMEP** (Supervisor mode execution protection) marks all userland pages in the page table as non-executable. This prevents the kernel from executing code in userland. This means that no userland code can run with kernel privileges.
1. **SMAP** (Supervisor mode access prevention) prevents data access to userland pages from kernel mode. This means that you also cannot read userland memory from the kernel unless you use `copy_to_user()` and `copy_from_user()`.
1. **KASLR** (Kernel address space layout randomisation) this is just aslr but in the kernel. There is a special kind called fg-kaslr but I will not go into details for it here.
1. **KPTI** (Kernel page-table isolation) This completely separates user-space and kernel-space page tables. With this, userland does not even know that the kernel exists, only a minimal trampoline is left to handle transitions between kernel and user safely.

#### Convenient protections that are not set:

1. **CONFIG_SLAB_FREELIST_RANDOM** makes it so that freed objects go into the freelist in a random order instead of LIFO like normal. Its not set here so it means that there will be no need to do any heap fengshui.
1. **CONFIG_STATIC_USERMODEHELPER** is not set so a modprobe path overwrite is possible (foreshadowing).
1. **CONFIG_SYSVIPC** is not set so there are msg_msg structs.

#### Modprobe path overwrite:

`modprobe` is a program used to load and unload kernel modules. The path to it is a kernel global variable, which by default is `/sbin/modprobe`. Very cool but how is it helpful? 

Well the path is stored in a kernel symbol `modprobe_path` and is also in a writable page. The program that is stored in `modprobe_path` also gets executed if we try to call `execve()` on a file whose magic bytes are unknown to the system. Sooooooooooooooooooo if we somehow overwrite `modprobe_path` and change the path to another program that we control, when a file with an unknown file signature is ran, that program is run in kernel mode which gives me arbitrary code execution with root privileges.

#### Binary analysis:

Now, I did the challenge with source code but during the actual event source code was not given so I shall also practice my ghidra skills here.


