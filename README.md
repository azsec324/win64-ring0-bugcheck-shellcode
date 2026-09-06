# win64-ring0-bugcheck-shellcode
## *Disclaimer*
*This repository and code hosted here is solely for education, security research and authorized testing purposes. The author does not condone or support any unauthorized or malicious use of this code.*
*By using or referencing this repository, you agree that you are solely responsible for your actions and any consequences resulting from the misuse of this material.*
## Description
This shellcode is for Windows/x64, intended to run under kernel-mode (Ring 0).

It loads value from MSR IA32_LSTAR(0xc0000082), uses it to scan for the base address of ntoskrnl.exe. It then attempts to locate KeBugCheck and calls it with value 0xDEADBEEF, resulting in an BSOD with that specific code (or could be caught by kernel debugger).

The shellcode is Null-Free and its length is 135 bytes.
