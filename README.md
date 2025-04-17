# HEVD-ArbitraryWrite
One way to exploit the Arbitrary-Write vulnerability

## Compiled with gcc under Windows (MinGW64):
    gcc -masm=intel ArbitraryWrite.c

## TARGET: 
    Windows 10 Home (VirtualBox) 
    1903
    Version	10.0.18362 Build 18362
    Systemtype x64

## DEMO:
  ![PoC](https://github.com/schxeat/HEVD-ArbitraryWrite/tree/main/resources/PoC.gif)

I discovered that guard_dispatch_icall only checks whether rax(=HalDispatchTable) is a kernel address. If rax is not a kernel address, a bug check is called. 
![1](https://github.com/schxeat/HEVD-ArbitraryWrite/tree/main/resources/guard_dispatch_call_1.png).
To ensure normal execution, I hooked HEVD-TriggerStackOverflow. This hook bypasses the check, and execution jumps to rax(=HEVD!TriggerBufferOverflowStack) 
![2](https://github.com/schxeat/HEVD-ArbitraryWrite/tree/main/resources/guard_dispatch_call_2.png)

For some reason, r11 is always set to '00000000`00000000', which causes the jump to 'nt!guard_dispatch_icall+0x31', which ultimately calls the shellcode.
