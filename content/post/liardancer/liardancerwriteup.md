+++
date = '2025-07-17T22:36:21+08:00'
draft = true
title = 'NYP Infosec June CTF 2025 Liardancer Writeup'
categories = ["writeup", "CTF"]
tags = ["heap", "pwn"]
+++

#### TLDR;

Liardancer is a heap pwn challenge from the June NYP Infosec 2025 CTF written by [cf](https://wrenches.online/nyp.html) (check her writeup out). 
It is a simple **tcache poisoning** into a **Global Offset Table(GOT)** overwrite, however with the security features of pointer mangling and the enforcement of 16 byte alignment for pointers returned by malloc().

#### Table of contents:
1. Prerequisites.
1. Binary and Source code Review.
1. Exploit.

#### Prerequisites
To do this exploit, we need to have a basic understanding of malloc(), free(), tcache , the GOT and the heap.

#### Here is a quick rundown, I ain't writing a lecture 

1. Heap is a region of dynamically allocated memory that the developer can request extra memory from.
1. `malloc()` is a function that requests memory from the heap. It returns a pointer to a chunk of memory.
1. `free()` is a function that releases the memory allocated by `malloc()` back into bins for recycling.
1. tcache is an example of a bin. When memory gets freed that chunk goes into the tcache which is a singly-linked list, so `malloc()` can quickly reuse these chunks without asking the system for new memory. 
1. Global Offset Table is a table that stores the addresses of external functions (like those from libc), allowing programs to resolve functions addresses at runtime via dynamic linking. 

#### Binary Protections

I like to use the protections to narrow down my options in exploitation, so this is my first step. 
1. **Partial RELRO** -- This means a GOT overwrite is possible.
1. **Stack Canary** -- This means that there is a secret value on the stack I must leak if I want to do a buffer overflow.
1. **NX enabled** -- This is a common protection that marks the stack as a non-executable(NX) region of memory, so shellcode cannot be executed. 
1. **No PIE** -- Position Independent Executable. This means that the binary starts at the same address each time, making exploitation much easier.

Since this binary is compiled against Glibc 2.38, there are some security features introduced to protect singly-linked lists like the tcache. 
1. 16 byte chunk alignment -- Which means that pointers returned by `malloc()` must be divisible by 16 (i.e., end in 0x0)
1. Pointer Mangling -- This is a basic form of pointer obfuscation. The forward pointer (fd) which points to the next free chunk in the list is not stored directly, instead, it goes through another step to obfuscate the pointer as shown below. 

`fd = (current_chunk_address >> 12) ^ next chunk in list(real fd)` 

`fd` is the value actually stored

`current_chunk_address` is the address of the chunk which is then bit shifted by 12 and XOR with the real fd.

#### Source Code Review
Upon opening the source code, I immediately saw the `win()` function staring at me, so I knew that I had to somehow redirect code execution back to that function to win.

![win function](/post/liardancer/images/winfunc.png)

I also included the sizes of the variables `MAX_DANCES` and `DANCE_SIZE`

This challenge has **3** main functionalities. A create, delete and edit. This instantly made me think that there was a possible Use-After-Free in the program so that's how I started digging. 

#### Create
`create_dance()` just allocates a chunk of 256 bytes at the index you desire, letting you add in some data too. It is also important to note the `printf()` function also prints out the address of the dance which will be our heap leak. **It is crucial to our exploit**.
![create dance](/post/liardancer/images/createdance.png)

#### Delete
`delete_dance()` frees the dance at the index you input. The problem is when a chunk is freed, the pointer still points to that chunk making a dangling pointer, and should be zeroed out by the developer like `dances[index] = NULL;` to prevent accessing freed memory. It is not done here. 
![delete dance](/post/liardancer/images/delete.png)

Now we know that there is a dangling pointer... I wonder if I could access it 🤔. 

#### Edit
`edit_dance()` lets you edit the data at the dance. Thats it. However, in combination with the dangling pointer from `delete_dance()`, we can edit the data of freed chunks. Hence, a Use-After-Free is born. 
![edit dance](/post/liardancer/images/edit.png)

#### tcache poisoning and GOT overwrite 
tcache poisoning aims to corrupt the fd(forward pointer) of the chunks in the tcache bin, tricking `malloc()` into returning a pointer to an arbitrary location. If my arbitrary location just so happens to be somewhere in the Global Offset Table(GOT), I can then overwrite the data at that entry to the address of `win()` during my `create_dance()`. Once done, the next time the program attempts to call the function, execution jumps to `win()`. Soooooooo...

#### GAMEPLAN
1. Corrupt fd pointer of a chunk. 
1. `malloc()` to get my pointer to GOT back so I can edit it.
1. Simultaneously change the data at that pointer to `win()` as part of the input for `create_dance()`
1. Call the function I edited. 
1. 💰 PROFIT!! 💰

#### Exploitation 
Since this binary has no PIE, the addresses are fixed so we can just go shopping for them first. We need the address of `win()` as well as the address of a victim entry in the GOT.

#### To find `win()` and victim entry:

`objdump -t chal` gives me the symbol table of the binary allowing me to easily find the address of `win()`.

![symbol table](/post/liardancer/images/symboltable.png)

`objdump -R chal` gives me the relocation table, which shows shows my GOT entries.

![relocation table](/post/liardancer/images/relocationtable.png)

Now to find a suitable victim, remember that the address of this victim must end in 0x0 and also be called relatively often and early in the program to avoid crashes. The most suitable option here would be `getchar()`.

#### Exploit script 
Here is the set up of my script.
![script set up](/post/liardancer/images/scriptsetup.png)

First, I create once and store the heap leak that I mentioned was crucial, it will be used in my pointer mangling step.
I create again, so now there are 2 chunks in the heap so that when I free it, **at least one chunk** will have a valid fd for me to corrupt.

![create twice](/post/liardancer/images/createtwice.png)

Next, I free both those chunks I created so they end up in the tcache.

![2free](/post/liardancer/images/2free.png)

This is a diagram showing the state of the tcache.

![tcachelayout](/post/liardancer/images/tcachelayout.png)

Then, using `edit_dance()`, I change the dance at 1 to my mangled address. 

![edit](/post/liardancer/images/edit1.png)

Here is another diagram to show you the overwrite.

![aftercorrupt](/post/liardancer/images/aftercorrupt.png)

After that, I `malloc()` twice, once to get chunk 1 back from the bin then once again to get the pointer to my GOT. Since in `create_dance()` I am able to input a dance description, I change it to `win()`. Next time the program calls `getchar()`, `win()` gets executed instead

![final step](/post/liardancer/images/finalstep1.png)

Andddd tada the flag is ours

![flag is ours](/post/liardancer/images/flagisours.png)

#### Stuff
Thanks for reading my first write up, I have no idea what I am doing, Thanks a lot. 

Special thanks to [Kaligula](https://kaligulaarmblessed.github.io/) for giving me the confidence to actually start a blog. Wahey!!!

This writeup was a little redemption arc for me as I could not solve this challenge during the actual competition so I did it now.

#### Super secret cool fun fact section
Astute readers might realise that in the pointer mangling step `fd = (current_chunk_address >> 12) ^ next chunk in list(real fd)`, I said that we have to use the current chunk's address but I used the address of chunk 0 as my `current_chunk_address` instead of the address of chunk 1 in the formula. This is because when we bitshift by 12, we essentially remove the lower 12 bits which are the distinct bits, leaving the top bits the same. 

For example,

chunk 0 at 0x555555559260

chunk 1 at 0x5555555592a0

When bitshifted by 12 

0x555555559260 >> 12 = 0x555555559

0x5555555592a0 >> 12 = 0x555555559

As you can see, they are the same so we can just use them interchangeably. As long as the chunks are allocated within the same 4kb memory page then `current_chunk_address >> 12` will always be the same.



