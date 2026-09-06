# win64-ring0-bugcheck-shellcode
## *Disclaimer*
*This repository and code hosted here is solely for education, security research and authorized testing purposes. The author does not condone or support any unauthorized or malicious use of this code.*
*By using or referencing this repository, you agree that you are solely responsible for your actions and any consequences resulting from the misuse of this material.*
## Description
This shellcode is for Windows/x64, intended to run under kernel-mode (Ring 0).

It loads value from MSR IA32_LSTAR(0xc0000082), uses it to scan for the base address of ntoskrnl.exe. It then attempts to locate KeBugCheck and calls it with value 0xDEADBEEF, resulting in an BSOD with that specific code (or could be caught by kernel debugger).

The shellcode is Null-Free and its length is 135 bytes.
## Details
The `binary_win64_bugcheck.txt` provides compiled binary in both Python and C compatible formats.

The assembly source is MASM compatible. In order to generate the binary, please run:
```
ml64 /c win64_bugcheck.asm
dumpbin /rawdata /section:.text$mn win64_bugcheck.obj
```
Last used MASM version 14.51.36256.0 for Visual Studio 2026

Tested on Windows 10 22H2 (OS Build 19045.6456, Kernel Base 10.0.19041.1) via directly replacing binary of a dummy function inside ntoskrnl.exe. Testing was done with WinDbg, the kernel debug log is located in the file `kernel_debug.log`.

This shellcode could still run at high IRQL (higher than Passive/APC). It is position independent and works when KASLR is enabled. It uses CPU MSR to get the address and doesn't rely on hardcoded offsets, so it should be theoretically able to run on any Windows 64-bit builds regardless of kernel versions, though this might need further testing as proof.
