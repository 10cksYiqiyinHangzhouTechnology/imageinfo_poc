#jpg 

[Project address](https://github.com/xiaozhuai/imageinfo)

# Build original project

```bash
cmake -B build .
cmake --build build -- all
cmake --build build -- check
```

# Build afl project

```
Cmakelist.txt add：

set (CMAKE_C_COMPILER "/usr/local/bin/afl-clang-fast")
set (CMAKE_CXX_COMPILER "/usr/local/bin/afl-clang-fast++")
```


# 02

## Vulnerability type

READ memory access causes SEGV stack overflow.

## ASAN

```bash
ubuntu@ubuntu:~/Desktop/imageinfo/imageinfo/build$ ./imageinfo ../../build/output/default/crashes/id\:000002\,sig\:11\,src\:000007\,time\:76911\,execs\:21200\,op\:havoc\,rep\:16 
AddressSanitizer:DEADLYSIGNAL
=================================================================
==3079903==ERROR: AddressSanitizer: SEGV on unknown address 0x6110010000bc (pc 0x555555583ae4 bp 0x7fffffffd7e0 sp 0x7fffffffd230 T0)
==3079903==The signal is caused by a READ memory access.
    #0 0x555555583ae3 in {lambda(unsigned long, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&)#1}::operator()(unsigned long, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&) const (/home/ubuntu/Desktop/imageinfo/imageinfo/build/imageinfo+0x2fae3)
    #1 0x5555555843c1 in _ZNSt17_Function_handlerIFbmR15IIReadInterfaceRlS2_RSt6vectorISt5arrayIlLm2EESaIS5_EEEUlmS1_S2_S2_S8_E_E9_M_invokeERKSt9_Any_dataOmS1_S2_S2_S8_ (/home/ubuntu/Desktop/imageinfo/imageinfo/build/imageinfo+0x303c1)
    #2 0x55555557cf11 in main (/home/ubuntu/Desktop/imageinfo/imageinfo/build/imageinfo+0x28f11)
    #3 0x7ffff7068082 in __libc_start_main ../csu/libc-start.c:308
    #4 0x55555556adad in _start (/home/ubuntu/Desktop/imageinfo/imageinfo/build/imageinfo+0x16dad)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV (/home/ubuntu/Desktop/imageinfo/imageinfo/build/imageinfo+0x2fae3) in {lambda(unsigned long, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&)#1}::operator()(unsigned long, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&) const
==3079903==ABORTING
```

## GDB

```bash
ubuntu@ubuntu:~/Desktop/imageinfo/build$ gdb --args ./imageinfo output/default/crashes/id\:000002\,sig\:11\,src\:000007\,time\:76911\,execs\:21200\,op\:havoc\,rep\:16 
GNU gdb (Ubuntu 9.2-0ubuntu1~20.04.1) 9.2
Copyright (C) 2020 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./imageinfo...

gdb-peda$ r output/default/crashes/id\:000002\,sig\:11\,src\:000007\,time\:76911\,execs\:21200\,op\:havoc\,rep\:16 
Starting program: /home/ubuntu/Desktop/imageinfo/build/imageinfo output/default/crashes/id\:000002\,sig\:11\,src\:000007\,time\:76911\,execs\:21200\,op\:havoc\,rep\:16

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
RAX: 0x65cb60 --> 0x726c646821000000 ('')
RBX: 0x6 
RCX: 0x100007c 
RDX: 0x87 
RSI: 0x4477a0 --> 0x0 
RDI: 0x4477a0 --> 0x0 
RBP: 0xf3000000 
RSP: 0x7fffffffda10 --> 0x7fffffffda58 --> 0x65cb60 --> 0x726c646821000000 ('')
RIP: 0x4113d1 (<std::_Function_handler<bool (unsigned long, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&), $_0>::_M_invoke(std::_Any_data const&, unsigned long&&, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&)+2561>:	mov    esi,DWORD PTR [rax+rcx*1])
R8 : 0x1 
R9 : 0x7fffffffda40 --> 0xf3 
R10: 0x40456b --> 0x5f007465736d656d ('memset')
R11: 0x7ffff7c61be0 --> 0x65cc50 --> 0x1a3809 
R12: 0x7fffffffdbd0 --> 0xffffffffffffffff 
R13: 0xf0ffffe6 
R14: 0x7fffffffdbd8 --> 0xffffffffffffffff 
R15: 0x4457b0 --> 0x4477a0 --> 0x0
EFLAGS: 0x10206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x4113c8 <std::_Function_handler<bool (unsigned long, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&), $_0>::_M_invoke(std::_Any_data const&, unsigned long&&, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&)+2552>:	add    bl,0x1
   0x4113cb <std::_Function_handler<bool (unsigned long, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&), $_0>::_M_invoke(std::_Any_data const&, unsigned long&&, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&)+2555>:	adc    bl,0x0
   0x4113ce <std::_Function_handler<bool (unsigned long, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&), $_0>::_M_invoke(std::_Any_data const&, unsigned long&&, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&)+2558>:	mov    BYTE PTR [rsi+rdx*1],bl
=> 0x4113d1 <std::_Function_handler<bool (unsigned long, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&), $_0>::_M_invoke(std::_Any_data const&, unsigned long&&, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&)+2561>:	mov    esi,DWORD PTR [rax+rcx*1]
   0x4113d4 <std::_Function_handler<bool (unsigned long, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&), $_0>::_M_invoke(std::_Any_data const&, unsigned long&&, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&)+2564>:	bswap  esi
   0x4113d6 <std::_Function_handler<bool (unsigned long, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&), $_0>::_M_invoke(std::_Any_data const&, unsigned long&&, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&)+2566>:	cmp    DWORD PTR [rax+rcx*1+0x4],0x70727069
   0x4113de <std::_Function_handler<bool (unsigned long, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&), $_0>::_M_invoke(std::_Any_data const&, unsigned long&&, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&)+2574>:	
    jne    0x411358 <std::_Function_handler<bool (unsigned long, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&), $_0>::_M_invoke(std::_Any_data const&, unsigned long&&, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&)+2440>:	    jne    0x411358 <std::_Function_handler<bool (unsigned long, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&), $_0>::_M_invoke(std::_Any_data const&, unsigned long&&, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&)+2440>
   0x4113e4 <std::_Function_handler<bool (unsigned long, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&), $_0>::_M_invoke(std::_Any_data const&, unsigned long&&, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&)+2580>:	
    jmp    0x41138d <std::_Function_handler<bool (unsigned long, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&), $_0>::_M_invoke(std::_Any_data const&, unsigned long&&, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&)+2493>:	    jmp    0x41138d <std::_Function_handler<bool (unsigned long, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&), $_0>::_M_invoke(std::_Any_data const&, unsigned long&&, IIReadInterface&, long&, long&, std::vector<std::array<long, 2ul>, std::allocator<std::array<long, 2ul> > >&)+2493>
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffda10 --> 0x7fffffffda58 --> 0x65cb60 --> 0x726c646821000000 ('')
0008| 0x7fffffffda18 --> 0x8 
0016| 0x7fffffffda20 --> 0x4 
0024| 0x7fffffffda28 --> 0x0 
0032| 0x7fffffffda30 --> 0x0 
0040| 0x7fffffffda38 --> 0x0 
0048| 0x7fffffffda40 --> 0xf3 
0056| 0x7fffffffda48 --> 0x7ffff7b052f6 (<_IO_new_file_fopen+534>:	mov    rbx,rax)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
$_0::operator() (this=<optimized out>, length=0x417, ri=..., width=<optimized out>, height=<optimized out>, entrySizes=...) at /home/ubuntu/Desktop/imageinfo/imageinfo.hpp:498
498	                        uint32_t boxSize = buffer.readU32BE(offset);
```

## Original code

```cpp
                    off_t offset = 0; // typedef long _off_t; off_t offset = 0;
                    off_t end = metaLength;

                    while (offset < end) {
                        uint32_t boxSize = buffer.readU32BE(offset); // uint32_t readU32BE;
                        if (buffer.cmpAnyOf(offset + 4, 4, {"iprp", "ipco"})) {
                            end = offset + boxSize;
                            offset += 8;
                        } else if (buffer.cmp(offset + 4, 4, "ispe")) {
                            width = buffer.readU32BE(offset + 12);
                            height = buffer.readU32BE(offset + 16);
                            return true;
                        } else {
                            offset += boxSize;
                        }
                    }
```
