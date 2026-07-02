+++
date = '2026-03-20T13:51:28+08:00'
draft = true
title = 'Puppypetsmart for Lag N Crash 6.0'
tags = ["heap", "pwn"]
+++

#### Introduction:

Welcome everybody, this is my third post on tcache poison, I seem to really like it... The tcache slop this time shall be on my challenge that was written for LNC6.0 

This was meant to be a kpwn challenge but I was told the CTF was too short and I also got skill issued on my own challenge so we have to make do with this.

#### Prerequisites:

Go read this post on the basics of tcache poisoning.

As usual, the binary will have **FULL RELRO** protection enabled, the binary's **Global Offset Table** (GOT) cannot be written to, so we shall do some Mile Cream Oriented Programming (Thank you sensei).

#### Source Code Review:

```c
show make
```


````c
show name
```

```c
show sell
```

```c
show read
```


