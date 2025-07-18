+++
date = '2025-07-17T22:36:21+08:00'
draft = true
title = 'NYP Infosec June CTF 2025 Liardancer Writeup'
categories = ["writeup", "CTF"]
tags = ["heap", "pwn"]
+++

### TLDR;

Liardancer is a heap pwn challenge from the June NYP Infosec 2025 written by ***cf***. 
It is a simple **tcache poisoning** into a **Global Offset Table(GOT)** overwrite, however with the security features of pointer mangling and the enforcement of 16 byte alignment for pointers returned by malloc().

### Prerequisites
To do this exploit, we need to have a basic understanding of malloc(), free(), tcache , the GOT and the heap.

#### Here is a quick run through, I ain't writing a lecture 

1. Heap is a region of dynamically allocated memory that the developer can request extra memory from.
1. `malloc()` is a function that requests memory from the heap. It returns a pointer to the chunk of memory.
1. `free()` is a function that releases the memory allocated by `malloc()` back into bins for recycling.
1. tcache is an example of a bin. When memory gets freed that chunk goes into the tcache which is a singly-linked list, so `malloc()` can quickly reuse these chunks without asking the system for new memory. 

### Binary Protections

I like to use the protections to narrow down my options in exploitation, so this is my first step. 
1. **Partial RELRO** -- This means a GOT overwrite is possible
1. **Stack Canary** -- This means that there is a secret value on the stack I must leak if I want to do a buffer overflow.
1. **NX enabled** -- This is a common protection that marks the stack as a non-executable(NX) region of memory, so shellcode cannot be executed. 
1. **No PIE** -- Position Independent Executable. This means that the binary starts at the same address each time, making exploitation much easier.
Since this binary is compiled against Glibc 2.38, there are some security features introduced to protect singly-linked lists like the tcache. 
1. 16 byte chunk alignment -- which means that pointers returned by `malloc()` must be divisible by 16 (i.e., end in 0x0)
1. Pointer Mangling -- This is a basic form of pointer obfuscation. The forward pointer (fd) which points to the next free chunk in the list is not stored directly, instead, it goes through another step to obfuscate the pointer as shown below. 

`fd = (chunk_address >> 12) ^ next chunk in list(real fd)` 

fd is the value actually stored
heap address is the address of the chunk which is then bit shifted by 12 and XOR with target address 

### Source Code Review
Upon opening the source code, I immediately saw the `win()` function staring at me, so I knew that I had to somehow redirect code execution back to that function to win.

This challenge has 3 main functionalities. A create, delete and edit. This instantly made me think that there was a possible Use-After-Free in the program so that's how I started digging. 

#### Create
`create_dance()` just allocates a chunk of 256 bytes at the index you desire, letting you add in some data too. It is also important to note the `printf()` function also prints out the address of the dance which will be our heap leak. **It is crucial to our exploit**.

#### Delete
`delete_dance()` frees the dance at the index you input. The problem is when a chunk is freed, the pointer still points to that chunk, a dangling pointer, and should be zeroed out by the developer like `dances[index] = NULL;` to prevent accessing freed memory.

Now we know that there is a dangling pointer... I wonder if I could access it. 

#### Edit
`edit_dance()` lets you edit the data at the dance. Thats it. However, in combination with the dangling pointer from `delete_dance()`, we can edit the data of freed chunks. Hence, a Use-After-Free is born. 

### tcache poisoning and GOT overwrite 
tcache poisoning aims to corrupt the fd(forward pointer) of the chunks in the tcache bin, tricking `malloc()` into returning a pointer to an arbitrary location. If my arbitrary location just so happens to be somewhere in the Global Offset Table(GOT), I can then make use of the `edit_dance()` function to edit the data at that entry to the address of `win()`. Once done, the next time the program attempts to call the function, execution jumps to `win()`. Soooooooo...

### GAMEPLAN
1. Corrupt fd pointer of a chunk. 
1. `malloc()` to get my 'chunk' at GOT back.
1. Use `edit_dance()` to change the data at the GOT address to `win()`. 
1. Call the function I edited. 
1. 💰 PROFIT!! 💰

### Exploit 
Since this binary has no PIE,the addresses are fixed so we can just go shopping for them first. We need the address of `win()` as well as the address of a victim entry in the GOT.

#### To find these:

`objdump -t chal` gives me the symbol table of the binary allowing me to easily find the address of `win()`.

`objdump -R chal` gives me the relocation table, which shows shows my GOT entries.

Now to find a suitable victim, remember that the address of this victim must end in 0x0 and also be called relatively often and early in the program to avoid crashes. The most suitable option here would be `printf()`. 

Next, I create once and store the heap leak that I mentioned was crucial, it will be used in my pointer mangling step.
I create again, so now there are 2 chunks in the heap so that when I free it, **at least one chunk will have a valid fd for me to corrupt. 

Consequently, I free both those chunks I created so they end up in the tcache.
show tcache bin here 

Then, using `edit_dance()`, I change the dance at 1 to my mangled address. 

After that, I `malloc()` twice, once to get chunk 1 back from the bin then once again to get the pointer to my GOT. Now the allocator thinks that the GOT address is a chunk, I am free to edit it however I want, so I edit it to `win()`. Next time the program calls `printf()`, `win()` gets executed instead

Andddd tada the flag is ours 


