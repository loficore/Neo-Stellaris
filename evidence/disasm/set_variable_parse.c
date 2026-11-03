; vtable 0x25EA560 slots (set_variable)
; slot[0] +0x00 = 0x18a8700
; slot[1] +0x08 = 0x3afd30
; slot[2] +0x10 = 0x188e0b0
; slot[3] +0x18 = 0x159730
; slot[4] +0x20 = 0x3b1770
; slot[5] +0x28 = 0x188e240
; slot[6] +0x30 = 0x3b1ef0
; slot[7] +0x38 = 0x3b2410
; slot[8] +0x40 = 0x3b0f80
; slot[9] +0x48 = 0x188e1d0
; slot[10] +0x50 = 0x3b1230
; slot[11] +0x58 = 0x1b2f30
; slot[12] +0x60 = 0x159730
; slot[13] +0x68 = 0x349640
; slot[14] +0x70 = 0x3b1330
; slot[15] +0x78 = 0x1848b40
; slot[16] +0x80 = 0x1b4550
; slot[17] +0x88 = 0x15db30
; slot[18] +0x90 = 0x188e170
; slot[19] +0x98 = 0x3b1420
; slot[20] +0xa0 = 0x3b1470
; slot[21] +0xa8 = 0x3b14b0
; slot[22] +0xb0 = 0x159730
; slot[23] +0xb8 = 0x3b2ad0
; slot[24] +0xc0 = 0x3b2b40
; stellaris.exe  .text RVA 0x188e240-0x188e330
  0188e240  mov     qword ptr [rsp + 0x18], rbx
  0188e245  mov     qword ptr [rsp + 0x10], rdx
  0188e24a  push    rbp
  0188e24b  push    rsi
  0188e24c  push    rdi
  0188e24d  lea     rbp, [rsp - 0x47]
  0188e252  sub     rsp, 0xc0
  0188e259  mov     rdi, rdx
  0188e25c  mov     rbx, rcx
  0188e25f  xor     esi, esi
  0188e261  mov     dword ptr [rbp - 0x39], esi
  0188e264  add     rcx, 0xf0
  0188e26b  lea     rdx, [rbp + 0x67]
  0188e26f  call    0x1403515a0  ; -> 0x3515a0
  0188e274  mov     eax, dword ptr [rbx + 0xe0]
  0188e27a  add     rbx, 0xd0
  0188e281  cmp     qword ptr [rbx + 0x18], 0x10
  0188e286  jb      0x14188e28b
  0188e288  mov     rbx, qword ptr [rbx]
  0188e28b  mov     qword ptr [rbp - 0x49], rbx
  0188e28f  mov     dword ptr [rbp - 0x41], eax
  0188e292  mov     byte ptr [rbp - 0x3d], sil
  0188e296  movaps  xmm0, xmmword ptr [rbp - 0x49]
  0188e29a  movdqa  xmmword ptr [rbp - 0x49], xmm0
  0188e29f  xor     r9d, r9d
  0188e2a2  xor     r8d, r8d
  0188e2a5  lea     rdx, [rbp - 0x49]
  0188e2a9  lea     rcx, [rbp - 1]
  0188e2ad  call    0x141cefeb0  ; -> 0x1cefeb0
  0188e2b2  nop     
  0188e2b3  movups  xmm2, xmmword ptr [rax]
  0188e2b6  movdqa  xmm0, xmm2
  0188e2ba  psrldq  xmm0, 8
  0188e2bf  movd    eax, xmm0
  0188e2c3  movsxd  r8, eax
  0188e2c6  mov     dword ptr [rbp - 0x31], esi
  0188e2c9  xorps   xmm0, xmm0
  0188e2cc  movdqu  xmmword ptr [rbp - 0x29], xmm0
  0188e2d1  movdqa  xmm1, xmmword ptr [rip + 0xe74397]  ; -> 0x2702670
  0188e2d9  movdqu  xmmword ptr [rbp - 0x11], xmm1
  0188e2de  mov     byte ptr [rbp - 0x21], 0
  0188e2e2  movq    rdx, xmm2
  0188e2e7  lea     rcx, [rbp - 0x31]
  0188e2eb  call    0x14015f770  ; -> 0x15f770
  0188e2f0  nop     
  0188e2f1  lea     rcx, [rbp - 1]
  0188e2f5  call    0x141cefd70  ; -> 0x1cefd70
  0188e2fa  nop     
  0188e2fb  lea     rax, [rip + 0xdacab6]  ; -> 0x263adb8
  0188e302  mov     qword ptr [rbp - 0x49], rax
  0188e306  mov     dword ptr [rbp - 0x41], 0xc
  0188e30d  mov     byte ptr [rbp - 0x3d], 0
  0188e311  movaps  xmm0, xmmword ptr [rbp - 0x49]
  0188e315  movdqa  xmmword ptr [rbp - 0x49], xmm0
  0188e31a  lea     rax, [rbp + 0x67]
  0188e31e  mov     qword ptr [rsp + 0x28], rax
  0188e323  lea     r9, [rbp - 0x31]
  0188e327  lea     rdx, [rbp - 0x49]
  0188e32b  lea     rcx, [rbp + 0xf]
; stellaris.exe  .text RVA 0x3b1770-0x3b17e0
  003b1770  mov     dword ptr [rsp + 0x20], r9d
  003b1775  mov     qword ptr [rsp + 0x10], rdx
  003b177a  push    rbp
  003b177b  push    rbx
  003b177c  push    rsi
  003b177d  push    rdi
  003b177e  push    r12
  003b1780  push    r13
  003b1782  push    r14
  003b1784  push    r15
  003b1786  lea     rbp, [rsp - 0x38]
  003b178b  sub     rsp, 0x138
  003b1792  mov     ebx, r9d
  003b1795  mov     r13, r8
  003b1798  mov     r14, rdx
  003b179b  mov     r12, rcx
  003b179e  xor     edi, edi
  003b17a0  mov     dword ptr [rsp + 0x20], edi
  003b17a4  mov     qword ptr [rbp + 0x20], r8
  003b17a8  inc     dword ptr [rip + 0x2fc2f36]  ; -> 0x33746e4
  003b17ae  mov     dword ptr [rbp - 0x40], edi
  003b17b1  xorps   xmm0, xmm0
  003b17b4  movdqu  xmmword ptr [rbp - 0x38], xmm0
  003b17b9  mov     qword ptr [rbp - 0x20], rdi
  003b17bd  mov     qword ptr [rbp - 0x18], 0xf
  003b17c5  mov     byte ptr [rbp - 0x30], dil
  003b17c9  mov     rax, qword ptr [rcx]
  003b17cc  call    qword ptr [rax + 0x58]
  003b17cf  test    al, al
  003b17d1  je      0x1403b1802
  003b17d3  test    ebx, ebx
  003b17d5  jle     0x1403b1802
  003b17d7  nop     word ptr [rax + rax]
