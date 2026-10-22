// source: ssh Windows_Jiaolong "python C:/ns/fridadis.py 0x1D08520 40"  (live attach, B3)
// target: stellaris.exe 4.4.4 sha256 9242c40abb78b53e88039ead1270ad82eb003959fb2d413c856d280ea02b1a56 (46,253,688 bytes)
// provenance: this list came from a RUNNING process via frida (read-only), NOT from scripts/cap.py's image read.
//   first line / count below is fridadis.py's own stdout header:
//     # disassembled 40 instructions from RVA 0x1d08520, 0 decode failures
//   column 1 is the byte offset from RVA 0x1d08520 (dis.js format string), not the absolute RVA.
//   §26 meeting lines: +0x0057 (the virtual call, slot[2] ExecuteActual) and +0x005a (the depth dec).
+0x0000  48 89 5c 24 08      mov qword ptr [rsp + 8], rbx
+0x0005  57                  push rdi
+0x0006  48 83 ec 20         sub rsp, 0x20
+0x000a  8b 42 08            mov eax, dword ptr [rdx + 8]
+0x000d  48 8b da            mov rbx, rdx
+0x0010  48 8b f9            mov rdi, rcx
+0x0013  85 c0               test eax, eax
+0x0015  78 32               js 0x7ff7d9ac8569
+0x0017  ba 10 00 00 00      mov edx, 0x10
+0x001c  48 8b cb            mov rcx, rbx
+0x001f  e8 7c 78 46 fe      call 0x7ff7d7f2fdc0
+0x0024  48 8b cb            mov rcx, rbx
+0x0027  e8 54 91 00 00      call 0x7ff7d9ad16a0
+0x002c  ba 03 00 00 00      mov edx, 3
+0x0031  48 8b cb            mov rcx, rbx
+0x0034  e8 67 78 46 fe      call 0x7ff7d7f2fdc0
+0x0039  ba 10 00 00 00      mov edx, 0x10
+0x003e  48 8b cb            mov rcx, rbx
+0x0041  e8 5a 78 46 fe      call 0x7ff7d7f2fdc0
+0x0046  8b 43 08            mov eax, dword ptr [rbx + 8]
+0x0049  ff c0               inc eax
+0x004b  48 8b d3            mov rdx, rbx
+0x004e  89 43 08            mov dword ptr [rbx + 8], eax
+0x0051  48 8b cf            mov rcx, rdi
+0x0054  48 8b 07            mov rax, qword ptr [rdi]
+0x0057  ff 50 10            call qword ptr [rax + 0x10]
+0x005a  ff 4b 08            dec dword ptr [rbx + 8]
+0x005d  48 8b cb            mov rcx, rbx
+0x0060  e8 1b 91 00 00      call 0x7ff7d9ad16a0
+0x0065  83 7b 08 00         cmp dword ptr [rbx + 8], 0
+0x0069  7c 1a               jl 0x7ff7d9ac85a5
+0x006b  ba 04 00 00 00      mov edx, 4
+0x0070  48 8b cb            mov rcx, rbx
+0x0073  e8 28 78 46 fe      call 0x7ff7d7f2fdc0
+0x0078  ba 10 00 00 00      mov edx, 0x10
+0x007d  48 8b cb            mov rcx, rbx
+0x0080  e8 1b 78 46 fe      call 0x7ff7d7f2fdc0
+0x0085  48 8b 5c 24 30      mov rbx, qword ptr [rsp + 0x30]
+0x008a  48 83 c4 20         add rsp, 0x20
+0x008e  5f                  pop rdi
