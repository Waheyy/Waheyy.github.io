+++
date = '2026-07-01T19:14:52+08:00'
draft = false
title = 'Procrastination is my salvation - msg_msg exploitation'
categories = ["writeup"]
tags = ["kernel", "pwn"]
+++

#### Introduction:

In my never-ending quest to do literally anything but schoolwork, I've gone back into the beautiful kpwn grind. I solved 3 challenges and will continue to procrastinate by posting writeups about them whenever I can, with the first challenge being Fire Of Salvation.

#### Table of Contents:

1. Vulnerability Analysis
1. Protections
1. `msg_msg` stuff
1. exploitation

#### Vulnerability Analysis:

This is a classic challenge which was my introduction into AAW and AAR with the `msg_msg` struct. 

The ioctl module revolves around letting users make firewall rules. The firewall rule object is allocated into `kmalloc-4K` which just so happens to be a size that can `msg_msg` fits into as well.

```c
typedef struct
{
    char iface[16];
    char name[16];
    uint32_t ip;
    uint32_t netmask;
    uint16_t proto;
    uint16_t port;
    uint8_t action;
    uint8_t is_duplicated;
    char desc[DESC_MAX]; //DESC_MAX = 0x800
} rule_t;
```


The UAF lies in the the `dup_rule` feature which allows you to dup an inbound rule to another array which holds the outbound rules, vice versa.

```c
static long firewall_add_rule(user_rule_t user_rule, rule_t **firewall_rules, uint8_t idx)
{
    printk(KERN_INFO "[Firewall::Info] firewall_add_rule() adding new rule!\n");

    if (firewall_rules[idx] != NULL)
    {
        printk(KERN_INFO "[Firewall::Error] firewall_add_rule() invalid rule slot!\n");
        return ERROR;
    }

    firewall_rules[idx] = (rule_t *)kzalloc(sizeof(rule_t), GFP_KERNEL);

    if (!firewall_rules[idx])
    {
        printk(KERN_INFO "[Firewall::Error] firewall_add_rule() allocation error!\n");
        return ERROR;
    }
// code continues but its just copying the fields to the object
```



```c
static long firewall_delete_rule(user_rule_t user_rule, rule_t **firewall_rules, uint8_t idx)
{
    printk(KERN_INFO "[Firewall::Info] firewall_delete_rule() deleting rule!\n");

    if (firewall_rules[idx] == NULL)
    {
        printk(KERN_INFO "[Firewall::Error] firewall_delete_rule() invalid rule slot!\n");
        return ERROR;
    }

    kfree(firewall_rules[idx]);
    firewall_rules[idx] = NULL;

    return SUCCESS;
}
```


As you can see here the delete rule actually nulls out the free after and is safe.


```c
static long firewall_dup_rule(user_rule_t user_rule, rule_t **firewall_rules, uint8_t idx)
{
    uint8_t i;
    rule_t **dup;

    printk(KERN_INFO "[Firewall::Info] firewall_dup_rule() duplicating rule!\n");

    dup = (user_rule.type == INBOUND) ? firewall_rules_out : firewall_rules_in;

    if (firewall_rules[idx] == NULL)
    {
        printk(KERN_INFO "[Firewall::Error] firewall_dup_rule() nothing to duplicate!\n");
        return ERROR;
    }

    if (firewall_rules[idx]->is_duplicated)
    {
        printk(KERN_INFO "[Firewall::Info] firewall_dup_rule() rule already duplicated before!\n");
        return ERROR;
    }

    for (i = 0; i < MAX_RULES; i++)
    {
        if (dup[i] == NULL)
        {
            dup[i] = firewall_rules[idx];
            firewall_rules[idx]->is_duplicated = 1;
            printk(KERN_INFO "[Firewall::Info] firewall_dup_rule() rule duplicated!\n");
            return SUCCESS;
        }
    }

    printk(KERN_INFO "[Firewall::Error] firewall_dup_rule() nowhere to duplicate!\n");

    return ERROR;
}
```


If you allocate an inbound rule then duplicate it to the outbound rule array and then proceed to free the inbound rule you just created, you will have a UAF as the rule is still accessible via the outbound rule array but it is freed.


```c
static long firewall_edit_rule(user_rule_t user_rule, rule_t **firewall_rules, uint8_t idx)
{
    printk(KERN_INFO "[Firewall::Info] firewall_edit_rule() editing rule!\n");

    printk(KERN_INFO "[Firewall::Error] Note that description editing is not implemented.\n");

    if (firewall_rules[idx] == NULL)
    {
        printk(KERN_INFO "[Firewall::Error] firewall_edit_rule() invalid idx!\n");
        return ERROR;
    }

    memcpy(firewall_rules[idx]->iface, user_rule.iface, 16);
    memcpy(firewall_rules[idx]->name, user_rule.name, 16);

    if (in4_pton(user_rule.ip, strnlen(user_rule.ip, 16), (u8 *)&(firewall_rules[idx]->ip), -1, NULL) == 0)
    {
        printk(KERN_ERR "[Firewall::Error] firewall_edit_rule() invalid IP format!\n");
        return ERROR;
    }

    if (in4_pton(user_rule.netmask, strnlen(user_rule.netmask, 16), (u8 *)&(firewall_rules[idx]->netmask), -1, NULL) == 0)
    {
        printk(KERN_ERR "[Firewall::Error] firewall_edit_rule() invalid Netmask format!\n");
        return ERROR;
    }

    firewall_rules[idx]->proto = user_rule.proto;
    firewall_rules[idx]->port = ntohs(user_rule.port);
    firewall_rules[idx]->action = user_rule.action;

    printk(KERN_ERR "[Firewall::Info] firewall_edit_rule() rule edited!\n");

    return SUCCESS;
}
```

In `edit_rule`, we get to freely write whatever we want to `iface` and `name` however to write to `ip` and `netmask` we must encode our value into a IP address format.

#### Protections:

Regarding protections, I will just go through a few important ones.
1. **CONFIG_SYSVIPC** is set so there are msg_msg structs. (The entire point of the challenge)
1. **FG-KASLR** is enabled so a regular kernel text leak will not work.
1. **CONFIG_STATIC_USERMODEHELPER** is enabled so no more modprobe path overwrite (crine).
1. **CONFIG_SLAB_FREELIST_RANDOM** is enabled so freed objects will be reclaimed in a random order which requires me to spray instead.

Of courses, there's your usual **SMAP** **SMEP** **KPTI** and **KASLR**.

#### MSG_MSG stuff:

`msg_msg` comes from the inter-process control system on Linux blah blah blah. I only care about the exploitation capability so we shall talk about that.

The size of the `msg_msg` struct can range from 0x40 to 0x1000 bytes and looks like this.

```c
struct msg_msg {
    struct list_head m_list;
    long m_type;
    size_t m_ts;        /* message text size */
    struct msg_msgseg *next;
    void *security; // will be null if no selinux is used
    /* the actual message follows immediately */
};
```

You can create `msg_msg` structs by making a message queue in userspace with `msgget(IPC_PRIVATE , IPC_CREAT | 0600);` and then calling `msgsnd(qid, buf, size, 0);` to send messages.

This creates a `msg_msg` struct in the kernel heap of size `0x30 + sizeof(msg)` with 0x30 being the metadata of the struct.

Messages go into a queue and are then returned to the user when `msgrcv(qid, rcvbuf , sizeof(rcvbuf), 0, IPC_NOWAIT | MSG_COPY | MSG_NOERROR)` is called.

**IPC_NOWAIT** means that if there are no messages the kernel will return `ENOMSG` instead of blocking the thread.

**MSG_COPY** can be used when `CONFIG_CHECKPOINT_RESTORE` is set which allows for the kernel to return a copy of the message instead of destroying it, maintaining the queue.

**MSG_NOERROR** just makes sure the message truncates instead of failing if the message is too long.

If the message is larger than 0x1000, then a `msg_msgseg` will be allocated which is the next segment of the message. It is like a linked list (neuron activation).

```c
struct msg_msgseg {
    struct msg_msgseg *next;
    /* the next part of the message follows immediately */
};
```


#### Getting an Arbitrary Address Read (AAR):

To get an arbitrary read, we can just overwrite the `next` field in the `msg_msg` and then read it back as long as `m_ts` is large enough to read into the next segment which will be the address you put.

However to even get an address to overwrite with, you will need a leak first. We can get a leak by controlling the size of the `msg_msg` so that `msg_msgseg` gets allocated from another cache like `kmalloc-32` for example, then we increase `m_ts` so that we can read past that `msg_msgseg` into adjacent objects which may container kernel pointers which will be our leak.


#### Getting an Arbtrary Address Write (AAW):

The arbitrary write is a little more complicated. The idea is to allocate a large message which causes a `msg_msgseg` to be allocated, before the message continues to the `msg_msgseg` you can edit the `next` pointer to the target address, causing your data to be written instead. A race condition. You can use the standard ways to extend the race, `USERFAULTFD`, `shmem`, `FUSE`.

Note: The addresses must start with a NULL QWORD so that there will not be another random linked list traversals.

#### Exploitation:

So the plan is simple, we get a UAF overlap with a `msg_msg` struct then I get an arbwrite and arbread.

Due to `FG-KASLR`, we must leak a pointer from the data section of the kernel. We can spray and read the `shm_file_data` objects which have a pointer to the data section in the `ipc_namespace` pointer.

```c
struct shm_file_data {
	int id;
	struct ipc_namespace *ns; //this fella
	struct file *file;
	const struct vm_operations_struct *vm_ops;
};
```

Using our UAF, we can change the `m_ts` field in our victim and then use `msgrcv()` to do our out of bounds read to the adjacent `shm_file_data` we sprayed beforehand.

Now we have our leaks, we can do our arbwrite but to where????

There is no modprobe path overwrite so what are my other targets?

We can overwrite the current task's cred and real_cred field to be `init_cred` instead but that requires to do task walking (very annoying).

Since symbols were provided (thank god) we can calculate the addresses of `init_task` and `init_cred`.

We use the UAF again to leak `init_task` and then traverse the task linked list till we find our current task. Once we find our current task we can overwrite the cred fields with `init_cred` and then profit YIPEE.

![win](/post/fireofsalvation/images/flag.png)

Very cool challenge. First time using `msg_msg` and userfaultfd.

References:

[my exploit](https://github.com/Waheyy/challenges/blob/main/fireofsalvation/exploit.c)

https://blog.smallkirby.com/posts/fire-of-salvation/

https://www.willsroot.io/2021/08/corctf-2021-fire-of-salvation-writeup.html


