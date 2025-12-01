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

In normal heap challenges, we get an arbitrary write via an arbitrary allocation once we perform tcache poisoning or any other attack that gives rise to an arbitrary allocation. Since the binary only has **Partial Relro** the plan is to do something is same same but a bit different. We still need leaks though, so lets tackle that.

#### Heap Leak:

#### Libc Leak:

After we get these 2 leaks, normally we could just get an arbitrary allocation to the Global Offset Table (GOT) and overwrite a GOT entry to `system()` but the problem we face here is that we lack the control over the arbitrary allocation. Here is a shameless plug for that kinda [challenge.](https://waheyy.github.io/post/liardancer/liardancerwriteup/)

Thinking for more time (I mean giving up and getting a hint from sensei), we realise that once we have a reference to `the_chunk` we are able to broaden our options more. Since `the_chunk` is a global variable, we can make use of the [unsafe_unlink](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/unsafe_unlink.c) attack to overwrite the value of `the_chunk`.

So we need the runtime address of `the_chunk`, which requires a PIE leak... but how the hell do we get one from this binary???

#### PIE Leak:

Seeing my struggle at getting the PIE Leak, my sensei bestowed some sacred knowledge onto me. This [article](https://nickgregory.me/post/2019/04/06/pivoting-around-memory/) talks about how to get leaks from other leaks and reading through it, you can see that you can leak PIE via the ld.




