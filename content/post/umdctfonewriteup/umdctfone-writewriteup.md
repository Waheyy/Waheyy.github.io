+++
date = '2025-12-01T12:54:09+08:00'
draft = true
title = 'Umdctf2025 One-Write, a beautiful heap challenge'
categories = ["writeup"]
tags = ["pwn", "heap"]
+++

#### Introduction:

WASSUP HOMIES, Mah name Tony! Welcome back to another text-based youtube video. One-Write is a challenge given to me by one of my dear senseis [ndgsghdj](https://ndgsghdj.github.io/article/1.html) who helped guide me along this entire challenge. This is the hardest heap challenge I've ever done and I want to go through the things I learnt in detail.

#### Table of Contents:

1. Protections
1. Binary Analysis
1. Exploit

#### Protections:

Protections always help narrow down the options, so running checksec we see,
1. **Partial Relro** - This means the GOT is writable and if I can gain an arbitrary write, this would be my main target for an code execution.

This is basically the only protection that matters in this case.

#### Binary Analysis:

Firstly we have some preamble,

show pic til prompt()

Now we have `alloc_chunk()`, it looks pretty normal, it lets you choose the index and size of the chunk but you do not get a write (Very sussy).

show pic of alloc_chunk

Then `free_chunk()` just frees a chunk at an index of your choosing. Note - It does not null the pointer, so we have a dangling pointer with potential for a Use-After-Free.

show pic of free_chunk

Here at `write_chunk()`, we see something interesting... We only have a 0x600-8 write to `the_chunk`.

Finally, at `read_chunk()` we also see that we only have a 0x600-8 read to `the_chunk`.

show pic of read_chunk

Finally finally, in `main()` we see that a 0x600-8 chunk is allocated and freed, its also not nulled. This means that we only have a 0x600 byte control over the heap starting from `the_chunk`, so everything we wanna do better end up in that 0x600 bytes.

Note - chunk_size-8 is an easy way to make sure that the allocated chunk falls in the right size bin.

#### Exploit:

In normal heap challenges, we get an arbitrary write via an arbitrary allocation once we perform tcache poisoning or any other attack that gives rise to an arbitrary allocation. Since the binary only has **Partial Relro** the plan is to do something that is same same but different. We still need leaks though, so lets tackle that.

#### Heap Leak:

The heap leak is your standard leak to get the heap key for pointer mangling.

```python
#mangle function takes in the heap key you leak and your target address and mangles it.
def mangle(key, fd):
    return (key) ^ fd

#here is the code i used for leaking the heap key.
alloc(2,16)
free(1)
free(2)
read()
p.recvuntil(b"> ")
heapleak = p.recvuntil(b"> ")[0x430:0x430+8]
heapleak = u64(heapleak.ljust(8, b"\x00"))
print(f"this is heapleak: {hex(heapleak)}")
alloc(3, 16)
```

The idea is that you allocate one thing and free it so it goes into tcache and read it back. Since the first chunk that goes into tcache will have its fd be NULL, NULL ^ heap key still gives heap key which is why we can just read it like that.

#### Libc Leak:

The libc leak is your standard unsorted bin leak, where you leak the `main_arena+96` address.

```python
alloc(0, 1056)
alloc(1, 16)
free(0)
read()
p.recvuntil(b"> ")
leak = p.recvuntil(b"> ")[:8]
leak = u64(leak.ljust(8, b"\x00"))
alloc(0,1056)
print(f"this is main_arena+96: {hex(leak)}")
main_arena = 0x1e7ac0
base = leak - main_arena - 96
```

After we get these 2 leaks, normally we could just get an arbitrary allocation to the Global Offset Table (GOT) and overwrite a GOT entry to `system()` but the problem we face here is that we lack the control over the arbitrary allocation. Here is a shameless plug for that kinda [challenge.](https://waheyy.github.io/post/liardancer/liardancerwriteup/)

Thinking for more time (I mean giving up and getting a hint from sensei), we realise that once we have a reference to `the_chunk` we are able to broaden our options more. Since `the_chunk` is a global variable, we can make use of the [unsafe_unlink](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/unsafe_unlink.c) attack to overwrite the value of `the_chunk`.

So we need the runtime address of `the_chunk`, which requires a PIE leak... but how the hell do we get one from this binary???

#### PIE Leak:

Seeing my struggle at getting the PIE Leak, my sensei bestowed some sacred knowledge onto me. This [article](https://nickgregory.me/post/2019/04/06/pivoting-around-memory/) talks about how to get leaks from other leaks and reading through it, you can see that you can leak PIE via the ld.

So first we need to get `_rtld_global` which is a constant offset from libc base and the first field of that struct is a pointer that holds the PIE base. So we do our usual tcache poison and get an arbitrary allocation at the pointer that holds the PIE base then we try to read it and we go "oh shit I don't have control over my arbitrary allocation so how the hell do I read." and so we now can talk about one of the beautiful parts of this challenge.

show pic

Since we corrupt A.fd to be the pointer of the PIE base (B), the fd of B will be the PIE base since the first 8 bytes at the pointer is PIE base since we have 3 in tcache. So we pull A and B out of tcache leaving PIE base inside then we free A again so that A.fd = PIE base and read A's fd. Absolutely genius brings a tear to my eyes I love pwn.

In the end, reading the fd of A once we freed it again, PIE base will be leak ^ (B >> 12) ^ (A >> 12).
Finally, we have a PIE leak god damn. Using it we get the address of `the_chunk`.

#### Unsafe Unlink attack:

We now interrupt your regularly scheduled program to go through the unsafe unlink attack, for all the homies who do not know what it is.

The entire attack is based around unlinking a node from a doubly linked list, if you took data structures and algorithms you would know how to do it.

show pic of normal unlinking

Let P be the chunk you want to unlink.

The normal unlinking operation goes like

**P -> fd -> bk = P.bk**
**P -> bk -> fd = P.fd**

Basically setting the bk of the fd of P to the bk of P to unlink P from the linked list and vice versa.

We also need to satisfy checks.

**P -> fd -> bk = P**
**P -> bk -> fd = P**

This is to make sure that arbitrary pointers dun get unlinked which is what happened in the old version of unsafe unlink before the check was added.

The general flow of the attack is (Go read [how2heap](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/unsafe_unlink.c) for details):
1. Allocate 2 chunks goes into unsorted bin. (e.g. 0x420)
1. Allocate a guard chunk to prevent consolidation.
1. Create a fake chunk in chunk 0(first chunk allocated).
1. Overwrite the metadata of chunk 1 (second chunk allocated), change the `prev_size` and `prev_inuse` bit
1. free chunk 1 so it consolidates the fake chunk inside chunk 0 and **unlinks** it.

#### Exploit continued...

We need to overwrite the global variable `the_chunk` to be a GOT entry so we can edit it. Since I did the unsafe_unlink with small bin sized chunks, we need to fill up tcache first so our chunks go into unsorted.

Once our chunks are in place, we can use the write functionality to make our fake chunk.

Free our victim chunk.

Now we have control over the GOT entry, I chose `atoi()` since there it takes one argument from user input. Overwrite `atoi()` to `system()` then BAM!! we have a shell.


This challenge was fun, made use of a lot of things I knew about but could not apply properly and also taught me how to use the unsafe unlink attack. 10/10 would recommend.







