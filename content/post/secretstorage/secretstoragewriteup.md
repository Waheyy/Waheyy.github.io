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

#### Setup stuff:

pic of req and box box size blah blah 

#### DO_CREATE:

Allocates a box into the GFG_KERNEL account. The size of box is 0x60 so it goes into the kmalloc-96 cache. You also can add a note in.

#### DO_READ:

Reads the name and note from the box into the buffer provided by the req struct.

#### DO_WRITE:

Writes a name and note to the box.

#### DO_RESIZE:

Resizes the note and copies the new note into it.

#### DO_DELETE:

Deletes a box and holy crap finally a vulnerability. The function frees the note and nulls it but when it frees the box it does not null it, leaving a dangling pointer that we can fandangle via a use-after-free(UAF).

#### Exploit:

Since KASLR is active, we are going to need a kernel leak to calculate the address of `modprobe path`. How in the frick frack snick snack do we do that here?

Well, in my experience so far, kernel heap challenges often get leaks by overlapping kernel structs instead of something like the unsorted bin libc leak in userland. Since I can read the boxes name and note, I wanna get something that fits into the kmalloc-96 cache and also gets me a kernel leak so scrolling through [this site](https://bsauce.github.io/2021/09/26/kernel-exploit-%E6%9C%89%E7%94%A8%E7%9A%84%E7%BB%93%E6%9E%84%E4%BD%93/) we find a struct called `subprocess_info` that fits into kmalloc-96 and `work.func` can be leaked to get the kernel base yipee.

So we allocate 2 boxes, box0 and box1. We free box0 then immediately reclaim its spot with a `subprocess_info` by calling `socket(22, AF_INET, 0)`.

Since box0 is deleted but not nulled we can still read it and ta da, we get the information that `subprocess_info` is holding.

This is the struct and we can see that it has a work_struct member then we dig deeper and we see that the work.func leak we need is at index 3 of the leaks.

If we start the qemu with root we can also check that the leak is pointing to `call_usermodehelper_exec_work`.

Since the address `call_usermodehelper_exec_work` and `modprobe_path` are all relative we can just do some math to find `modprobe_path`.
comment the eqn i did 

Now that we have the `modprobe_path` address we need to resize the note to go into 0x60 cache and overwrite over box0 again and make sure that the new note size is big enough and the note address is the address of `modprobe_path`.

Then we write to box0 with the new note being the path of the script that I want ran with root privileges.

The script basically copies the stuff in `/dev/sda` into `/tmp/flag` as well as granting it full permissions and makes it executable. Then it makes an unknown file and runs it which should then trigger `modprobe_path` and run the script and now the flag from `/dev/sda` is inside `/tmp/flag` and we can view it

WAHEY! It worked, that's fantabbitastic.

Overall, this challenge was very fun and got me thinking in the kernel pwn mindset instead of the userland pwn mindset and serves as a great introduction to possible kernel structs and how the kernel heap works.

Anyways, that's it for this text based youtube video. Please make sure to like 👍 and soobscribe and make sure to turn on the notification bell🔔 and see you guys [next time](https://youtu.be/oC2zvQ6B1Dw?si=Roa2V2vUd-jVzFRb).









