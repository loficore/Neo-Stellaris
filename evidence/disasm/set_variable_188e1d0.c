; stellaris.exe  .text RVA 0x188e1d0-0x188e234
  0188e1d0  mov     qword ptr [rsp + 0x10], rbx
  0188e1d5  mov     qword ptr [rsp + 0x18], rsi
  0188e1da  push    rdi
  0188e1db  sub     rsp, 0x20
  0188e1df  mov     rsi, rdx
  0188e1e2  mov     rdi, rcx
  0188e1e5  mov     r8, rdx
  0188e1e8  add     rcx, 0xf0
  0188e1ef  lea     rdx, [rsp + 0x30]
  0188e1f4  call    0x1403515a0  ; -> 0x3515a0
  0188e1f9  mov     rbx, qword ptr [rsp + 0x30]
  0188e1fe  lea     rdx, [rdi + 0xc0]
  0188e205  mov     rcx, rsi
  0188e208  call    0x140a56cc0  ; -> 0xa56cc0
  0188e20d  test    rax, rax
  0188e210  je      0x14188e224
  0188e212  mov     r8, rbx
  0188e215  lea     rdx, [rdi + 0xc0]
  0188e21c  mov     rcx, rax
  0188e21f  call    0x1407eebf0  ; -> 0x7eebf0
  0188e224  mov     rbx, qword ptr [rsp + 0x38]
  0188e229  mov     rsi, qword ptr [rsp + 0x40]
  0188e22e  add     rsp, 0x20
  0188e232  pop     rdi
  0188e233  ret     
; stellaris.exe  .text RVA 0x3515a0-0x351b80
  003515a0  mov     qword ptr [rsp + 8], rbx
  003515a5  push    rdi
  003515a6  sub     rsp, 0x1a0
  003515ad  mov     r10, r8
  003515b0  mov     rdi, rdx
  003515b3  mov     rbx, rcx
  003515b6  cmp     qword ptr [rcx + 0x210], 0
  003515be  jne     0x1403515cf
  003515c0  mov     rax, qword ptr [rcx + 0x220]
  003515c7  mov     qword ptr [rdx], rax
  003515ca  jmp     0x140351b64  ; -> 0x351b64
  003515cf  cmp     byte ptr [rcx + 0x1a0], 0
  003515d6  jne     0x140351a57
  003515dc  cmp     dword ptr [rcx + 0x19c], 0
  003515e3  jne     0x140351a57
  003515e9  mov     ecx, dword ptr [rcx + 0x70]
  003515ec  cmp     ecx, 0x31e3
  003515f2  jg      0x1403517f2
  003515f8  je      0x140351a57
  003515fe  cmp     ecx, 0x2bc7
  00351604  jg      0x1403516a4
  0035160a  je      0x140351a57
  00351610  cmp     ecx, 0x2a14
  00351616  jg      0x140351667
  00351618  je      0x140351a57
  0035161e  sub     ecx, 0x6b
  00351621  je      0x140351a57
  00351627  sub     ecx, 0x26c2
  0035162d  je      0x140351a57
  00351633  sub     ecx, 0xe1
  00351639  je      0x140351a57
  0035163f  sub     ecx, 0x204
  00351645  je      0x140351a57
  0035164b  cmp     ecx, 1
  0035164e  je      0x140351a57
  00351654  mov     r8, r10
  00351657  mov     rdx, rdi
  0035165a  mov     rcx, rbx
  0035165d  call    0x140352500  ; -> 0x352500
  00351662  jmp     0x140351b64  ; -> 0x351b64
  00351667  sub     ecx, 0x2a24
  0035166d  je      0x140351a57
  00351673  sub     ecx, 0x53
  00351676  je      0x140351a57
  0035167c  sub     ecx, 0xa4
  00351682  je      0x140351a57
  00351688  cmp     ecx, 0x31
  0035168b  je      0x140351a57
  00351691  mov     r8, r10
  00351694  mov     rdx, rdi
  00351697  mov     rcx, rbx
  0035169a  call    0x140352500  ; -> 0x352500
  0035169f  jmp     0x140351b64  ; -> 0x351b64
  003516a4  cmp     ecx, 0x2cf3
  003516aa  jg      0x1403516e2
  003516ac  je      0x140351a57
  003516b2  sub     ecx, 0x2bcd
  003516b8  cmp     ecx, 0xfd
  003516be  ja      0x140351a6c
  003516c4  movsxd  rax, ecx
  003516c7  lea     rdx, [rip - 0x3516ce]  ; -> 0x0
  003516ce  movzx   eax, byte ptr [rdx + rax + 0x351b80]
  003516d6  mov     ecx, dword ptr [rdx + rax*4 + 0x351b78]
  003516dd  add     rcx, rdx
  003516e0  jmp     rcx
  003516e2  cmp     ecx, 0x2e58
  003516e8  jg      0x140351779
  003516ee  je      0x140351a57
  003516f4  cmp     ecx, 0x2dba
  003516fa  jg      0x14035173f
  003516fc  je      0x140351a57
  00351702  sub     ecx, 0x2cf4
  00351708  je      0x140351a57
  0035170e  sub     ecx, 1
  00351711  je      0x140351a57
  00351717  sub     ecx, 1
  0035171a  je      0x140351a57
  00351720  cmp     ecx, 0x9f
  00351726  je      0x140351a57
  0035172c  mov     r8, r10
  0035172f  mov     rdx, rdi
  00351732  mov     rcx, rbx
  00351735  call    0x140352500  ; -> 0x352500
  0035173a  jmp     0x140351b64  ; -> 0x351b64
  0035173f  sub     ecx, 0x2e2a
  00351745  je      0x140351a57
  0035174b  sub     ecx, 0x15
  0035174e  je      0x140351a57
  00351754  sub     ecx, 0x10
  00351757  je      0x140351a57
  0035175d  cmp     ecx, 1
  00351760  je      0x140351a57
  00351766  mov     r8, r10
  00351769  mov     rdx, rdi
  0035176c  mov     rcx, rbx
  0035176f  call    0x140352500  ; -> 0x352500
  00351774  jmp     0x140351b64  ; -> 0x351b64
  00351779  cmp     ecx, 0x30e7
  0035177f  jg      0x1403517c1
  00351781  je      0x140351a57
  00351787  sub     ecx, 0x2e84
  0035178d  je      0x140351a57
  00351793  sub     ecx, 0xa
  00351796  je      0x140351a57
  0035179c  sub     ecx, 0x5a
  0035179f  je      0x140351a57
  003517a5  cmp     ecx, 1
  003517a8  je      0x140351a57
  003517ae  mov     r8, r10
  003517b1  mov     rdx, rdi
  003517b4  mov     rcx, rbx
  003517b7  call    0x140352500  ; -> 0x352500
  003517bc  jmp     0x140351b64  ; -> 0x351b64
  003517c1  sub     ecx, 0x30f1
  003517c7  je      0x140351a57
  003517cd  sub     ecx, 0x15
  003517d0  je      0x140351a57
  003517d6  cmp     ecx, 0x6d
  003517d9  je      0x140351a57
  003517df  mov     r8, r10
  003517e2  mov     rdx, rdi
  003517e5  mov     rcx, rbx
  003517e8  call    0x140352500  ; -> 0x352500
  003517ed  jmp     0x140351b64  ; -> 0x351b64
  003517f2  cmp     ecx, 0x333c
  003517f8  jg      0x140351830
  003517fa  je      0x140351a57
  00351800  sub     ecx, 0x3223
  00351806  cmp     ecx, 0xa5
  0035180c  ja      0x140351a6c
  00351812  movsxd  rax, ecx
  00351815  lea     rdx, [rip - 0x35181c]  ; -> 0x0
  0035181c  movzx   eax, byte ptr [rdx + rax + 0x351c88]
  00351824  mov     ecx, dword ptr [rdx + rax*4 + 0x351c80]
  0035182b  add     rcx, rdx
  0035182e  jmp     rcx
  00351830  cmp     ecx, 0x3f71
  00351836  jg      0x140351973
  0035183c  je      0x140351a57
  00351842  cmp     ecx, 0x3ac0
  00351848  jg      0x1403518eb
  0035184e  je      0x140351a57
  00351854  cmp     ecx, 0x36cb
  0035185a  jg      0x1403518a8
  0035185c  je      0x140351a57
  00351862  sub     ecx, 0x3365
  00351868  je      0x140351a57
  0035186e  sub     ecx, 1
  00351871  je      0x140351a57
  00351877  sub     ecx, 0x3f
  0035187a  je      0x140351a57
  00351880  sub     ecx, 0x6c
  00351883  je      0x140351a57
  00351889  cmp     ecx, 0x1a8
  0035188f  je      0x140351a57
  00351895  mov     r8, r10
  00351898  mov     rdx, rdi
  0035189b  mov     rcx, rbx
  0035189e  call    0x140352500  ; -> 0x352500
  003518a3  jmp     0x140351b64  ; -> 0x351b64
  003518a8  cmp     ecx, 0x3844
  003518ae  je      0x140351a57
  003518b4  cmp     ecx, 0x391e
  003518ba  je      0x140351a57
  003518c0  cmp     ecx, 0x3a0c
  003518c6  je      0x140351a57
  003518cc  cmp     ecx, 0x3abf
  003518d2  je      0x140351a57
  003518d8  mov     r8, r10
  003518db  mov     rdx, rdi
  003518de  mov     rcx, rbx
  003518e1  call    0x140352500  ; -> 0x352500
  003518e6  jmp     0x140351b64  ; -> 0x351b64
  003518eb  cmp     ecx, 0x3e25
  003518f1  jg      0x140351936
  003518f3  je      0x140351a57
  003518f9  sub     ecx, 0x3c31
  003518ff  je      0x140351a57
  00351905  sub     ecx, 0x1d
  00351908  je      0x140351a57
  0035190e  sub     ecx, 0xa8
  00351914  je      0x140351a57
  0035191a  cmp     ecx, 4
  0035191d  je      0x140351a57
  00351923  mov     r8, r10
  00351926  mov     rdx, rdi
  00351929  mov     rcx, rbx
  0035192c  call    0x140352500  ; -> 0x352500
  00351931  jmp     0x140351b64  ; -> 0x351b64
  00351936  sub     ecx, 0x3e84
  0035193c  je      0x140351a57
  00351942  sub     ecx, 0x23
  00351945  je      0x140351a57
  0035194b  sub     ecx, 0xa2
  00351951  je      0x140351a57
  00351957  cmp     ecx, 1
  0035195a  je      0x140351a57
  00351960  mov     r8, r10
  00351963  mov     rdx, rdi
  00351966  mov     rcx, rbx
  00351969  call    0x140352500  ; -> 0x352500
  0035196e  jmp     0x140351b64  ; -> 0x351b64
  00351973  cmp     ecx, 0x42bf
  00351979  jg      0x140351a06
  0035197f  je      0x140351a57
  00351985  cmp     ecx, 0x405a
  0035198b  jg      0x1403519d6
  0035198d  je      0x140351a57
  00351993  sub     ecx, 0x3fd9
  00351999  je      0x140351a57
  0035199f  sub     ecx, 1
  003519a2  je      0x140351a57
  003519a8  sub     ecx, 0x24
  003519ab  je      0x140351a57
  003519b1  sub     ecx, 0x55
  003519b4  je      0x140351a57
  003519ba  cmp     ecx, 6
  003519bd  je      0x140351a57
  003519c3  mov     r8, r10
  003519c6  mov     rdx, rdi
  003519c9  mov     rcx, rbx
  003519cc  call    0x140352500  ; -> 0x352500
  003519d1  jmp     0x140351b64  ; -> 0x351b64
  003519d6  sub     ecx, 0x4070
  003519dc  je      0x140351a57
  003519de  sub     ecx, 0x179
  003519e4  je      0x140351a57
  003519e6  sub     ecx, 0x2c
  003519e9  je      0x140351a57
  003519eb  cmp     ecx, 0xa4
  003519f1  je      0x140351a57
  003519f3  mov     r8, r10
  003519f6  mov     rdx, rdi
  003519f9  mov     rcx, rbx
  003519fc  call    0x140352500  ; -> 0x352500
  00351a01  jmp     0x140351b64  ; -> 0x351b64
  00351a06  cmp     ecx, 0x4598
  00351a0c  jg      0x140351a40
  00351a0e  je      0x140351a57
  00351a10  sub     ecx, 0x42dd
  00351a16  je      0x140351a57
  00351a18  sub     ecx, 0x131
  00351a1e  je      0x140351a57
  00351a20  sub     ecx, 0x37
  00351a23  je      0x140351a57
  00351a25  cmp     ecx, 0x81
  00351a2b  je      0x140351a57
  00351a2d  mov     r8, r10
  00351a30  mov     rdx, rdi
  00351a33  mov     rcx, rbx
  00351a36  call    0x140352500  ; -> 0x352500
  00351a3b  jmp     0x140351b64  ; -> 0x351b64
  00351a40  sub     ecx, 0x4599
  00351a46  je      0x140351a57
  00351a48  sub     ecx, 1
  00351a4b  je      0x140351a57
  00351a4d  sub     ecx, 0xe
  00351a50  je      0x140351a57
  00351a52  cmp     ecx, 7
  00351a55  jne     0x140351a6c
  00351a57  mov     rcx, qword ptr [rbx + 0x190]
  00351a5e  test    rcx, rcx
  00351a61  je      0x140351a7f
  00351a63  call    0x1403533b0  ; -> 0x3533b0
  00351a68  test    al, al
  00351a6a  jne     0x140351a7f
  00351a6c  mov     r8, r10
  00351a6f  mov     rdx, rdi
  00351a72  mov     rcx, rbx
  00351a75  call    0x140352500  ; -> 0x352500
  00351a7a  jmp     0x140351b64  ; -> 0x351b64
  00351a7f  xor     r9d, r9d
  00351a82  mov     r8, r10
  00351a85  lea     rdx, [rsp + 0x30]
  00351a8a  lea     rcx, [rbx + 8]
  00351a8e  call    0x140356be0  ; -> 0x356be0
  00351a93  nop     
  00351a94  lea     rcx, [rsp + 0x30]
  00351a99  call    0x140395730  ; -> 0x395730
  00351a9e  test    al, al
  00351aa0  jne     0x140351af7
  00351aa2  lea     rax, [rip + 0x21762b7]  ; -> 0x24c7d60
  00351aa9  mov     qword ptr [rsp + 0x20], rax
  00351aae  mov     dword ptr [rsp + 0x28], 0x129
  00351ab6  mov     dword ptr [rsp + 0x2c], 0x1000
  00351abe  lea     r9, [rbx + 0x200]
  00351ac5  cmp     qword ptr [r9 + 0x18], 0x10
  00351aca  jb      0x140351acf
  00351acc  mov     r9, qword ptr [r9]
  00351acf  lea     r8, [rbx + 0x48]
  00351ad3  cmp     qword ptr [r8 + 0x18], 0x10
  00351ad8  jb      0x140351add
  00351ada  mov     r8, qword ptr [r8]
  00351add  lea     rdx, [rip + 0x2176314]  ; -> 0x24c7df8
  00351ae4  lea     rcx, [rsp + 0x20]
  00351ae9  call    0x141c91c30  ; -> 0x1c91c30
  00351aee  mov     qword ptr [rdi], 0
  00351af5  jmp     0x140351b08  ; -> 0x351b08
  00351af7  lea     r8, [rsp + 0x30]
  00351afc  mov     rdx, rdi
  00351aff  mov     rcx, rbx
  00351b02  call    0x140352500  ; -> 0x352500
  00351b07  nop     
  00351b08  lea     rcx, [rsp + 0xa0]
  00351b10  call    0x14023ad30  ; -> 0x23ad30
  00351b15  mov     rcx, qword ptr [rsp + 0x90]
  00351b1d  test    rcx, rcx
  00351b20  je      0x140351b2c
  00351b22  mov     rax, qword ptr [rcx]
  00351b25  mov     edx, 1
  00351b2a  call    qword ptr [rax]
  00351b2c  mov     rcx, qword ptr [rsp + 0x88]
  00351b34  test    rcx, rcx
  00351b37  je      0x140351b43
  00351b39  mov     rax, qword ptr [rcx]
  00351b3c  mov     edx, 1
  00351b41  call    qword ptr [rax]
  00351b43  mov     rcx, qword ptr [rsp + 0x80]
  00351b4b  test    rcx, rcx
  00351b4e  je      0x140351b5a
  00351b50  mov     rax, qword ptr [rcx]
  00351b53  mov     edx, 1
  00351b58  call    qword ptr [rax]
  00351b5a  mov     rcx, qword ptr [rsp + 0x78]
  00351b5f  call    0x14023a500  ; -> 0x23a500
  00351b64  mov     rax, rdi
  00351b67  mov     rbx, qword ptr [rsp + 0x1b0]
  00351b6f  add     rsp, 0x1a0
  00351b76  pop     rdi
  00351b77  ret     
  00351b78  push    rdi
  00351b79  sbb     dh, byte ptr [rip + 0x351a6c00]  ; -> 0x354f877f
; stellaris.exe  .text RVA 0x7eebf0-0x7eec80
  007eebf0  mov     qword ptr [rsp + 8], rbx
  007eebf5  mov     qword ptr [rsp + 0x18], r8
  007eebfa  push    rdi
  007eebfb  sub     rsp, 0x40
  007eebff  mov     rbx, rdx
  007eec02  lea     rdi, [rcx + 8]
  007eec06  add     rdx, 0x10
  007eec0a  cmp     qword ptr [rdx + 0x18], 0x10
  007eec0f  jb      0x1407eec14
  007eec11  mov     rdx, qword ptr [rdx]
  007eec14  mov     r8d, dword ptr [rbx + 0x20]
  007eec18  xor     ecx, ecx
  007eec1a  call    0x141c9e350  ; -> 0x1c9e350
  007eec1f  lea     rcx, [rsp + 0x60]
  007eec24  mov     r9, rbx
  007eec27  mov     qword ptr [rsp + 0x20], rcx
  007eec2c  lea     rdx, [rsp + 0x30]
  007eec31  mov     rcx, rdi
  007eec34  mov     r8d, eax
  007eec37  call    0x1407ef5d0  ; -> 0x7ef5d0
  007eec3c  cmp     byte ptr [rsp + 0x38], 0
  007eec41  jne     0x1407eec51
  007eec43  mov     rax, qword ptr [rsp + 0x30]
  007eec48  mov     rcx, qword ptr [rsp + 0x60]
  007eec4d  mov     qword ptr [rax + 0x38], rcx
  007eec51  mov     rbx, qword ptr [rsp + 0x50]
  007eec56  add     rsp, 0x40
  007eec5a  pop     rdi
  007eec5b  ret     
  007eec5c  int3    
  007eec5d  int3    
  007eec5e  int3    
  007eec5f  int3    
  007eec60  mov     qword ptr [rsp + 0x10], rbx
  007eec65  mov     qword ptr [rsp + 0x18], rsi
  007eec6a  push    rdi
  007eec6b  sub     rsp, 0x20
  007eec6f  lea     rsi, [rcx + 8]
  007eec73  mov     r8, rdx
  007eec76  lea     rdx, [rsp + 0x30]
  007eec7b  mov     rcx, rsi
; stellaris.exe  .text RVA 0x18a6970-0x18a69c0
  018a6970  push    rbx
  018a6972  sub     rsp, 0x20
  018a6976  mov     ecx, 0x318
  018a697b  call    0x142185218  ; -> 0x2185218
  018a6980  mov     rbx, rax
  018a6983  mov     qword ptr [rsp + 0x38], rax
  018a6988  xor     edx, edx
  018a698a  mov     r8d, 0x318
  018a6990  mov     rcx, rax
  018a6993  call    0x142188170  ; -> 0x2188170
  018a6998  mov     rcx, rbx
  018a699b  call    0x1418a71a0  ; -> 0x18a71a0
  018a69a0  lea     rax, [rip + 0xd43bb9]  ; -> 0x25ea560
  018a69a7  mov     qword ptr [rbx], rax
  018a69aa  lea     rax, [rip + 0xd439cf]  ; -> 0x25ea380
  018a69b1  mov     qword ptr [rbx + 8], rax
  018a69b5  mov     rax, rbx
  018a69b8  add     rsp, 0x20
  018a69bc  pop     rbx
  018a69bd  ret     
  018a69be  int3    
  018a69bf  int3    
; stellaris.exe  .text RVA 0x18a71a0-0x18a7232
  018a71a0  mov     qword ptr [rsp + 0x18], rbx
  018a71a5  mov     qword ptr [rsp + 0x20], rsi
  018a71aa  mov     qword ptr [rsp + 8], rcx
  018a71af  push    rdi
  018a71b0  sub     rsp, 0x20
  018a71b4  mov     rdi, rcx
  018a71b7  call    0x1403afb40  ; -> 0x3afb40
  018a71bc  nop     
  018a71bd  lea     rax, [rip + 0xd61d04]  ; -> 0x2608ec8
  018a71c4  mov     qword ptr [rdi], rax
  018a71c7  lea     rax, [rip + 0xd431b2]  ; -> 0x25ea380
  018a71ce  mov     qword ptr [rdi + 8], rax
  018a71d2  xor     esi, esi
  018a71d4  mov     dword ptr [rdi + 0xc0], esi
  018a71da  mov     qword ptr [rdi + 0xc8], rsi
  018a71e1  mov     qword ptr [rdi + 0xd0], rsi
  018a71e8  mov     qword ptr [rdi + 0xe0], rsi
  018a71ef  mov     qword ptr [rdi + 0xe8], 0xf
  018a71fa  lea     rbx, [rdi + 0xf0]
  018a7201  mov     qword ptr [rsp + 0x38], rbx
  018a7206  mov     rcx, rbx
  018a7209  call    0x14034ecd0  ; -> 0x34ecd0
  018a720e  lea     rax, [rip + 0xc0c3ab]  ; -> 0x24b35c0
  018a7215  mov     qword ptr [rbx], rax
  018a7218  mov     qword ptr [rbx + 0x220], rsi
  018a721f  mov     rax, rdi
  018a7222  mov     rbx, qword ptr [rsp + 0x40]
  018a7227  mov     rsi, qword ptr [rsp + 0x48]
  018a722c  add     rsp, 0x20
  018a7230  pop     rdi
  018a7231  ret     
; stellaris.exe  .text RVA 0x34ecd0-0x34ed5b
  0034ecd0  push    rbx
  0034ecd2  sub     rsp, 0x20
  0034ecd6  lea     rax, [rip + 0x21648d3]  ; -> 0x24b35b0
  0034ecdd  mov     rbx, rcx
  0034ece0  mov     qword ptr [rcx], rax
  0034ece3  add     rcx, 8
  0034ece7  call    0x140353bd0  ; -> 0x353bd0
  0034ecec  xor     eax, eax
  0034ecee  mov     dword ptr [rbx + 0x1a8], 0x7fffffff
  0034ecf8  mov     qword ptr [rbx + 0x1b0], rax
  0034ecff  mov     qword ptr [rbx + 0x1b8], rax
  0034ed06  mov     dword ptr [rbx + 0x1c0], eax
  0034ed0c  mov     qword ptr [rbx + 0x1c8], rax
  0034ed13  mov     qword ptr [rbx + 0x1d0], rax
  0034ed1a  mov     qword ptr [rbx + 0x1e0], rax
  0034ed21  mov     qword ptr [rbx + 0x1e8], 0xf
  0034ed2c  mov     dword ptr [rbx + 0x1f0], eax
  0034ed32  mov     qword ptr [rbx + 0x1f8], rax
  0034ed39  mov     qword ptr [rbx + 0x200], rax
  0034ed40  mov     qword ptr [rbx + 0x210], rax
  0034ed47  mov     rax, rbx
  0034ed4a  mov     qword ptr [rbx + 0x218], 0xf
  0034ed55  add     rsp, 0x20
  0034ed59  pop     rbx
  0034ed5a  ret     
; stellaris.exe  .text RVA 0x1c9e350-0x1c9e3d6
  01c9e350  push    rbx
  01c9e352  sub     rsp, 0x20
  01c9e356  mov     ebx, r8d
  01c9e359  mov     dword ptr [rsp + 0x30], ecx
  01c9e35d  mov     r9d, r8d
  01c9e360  mov     dword ptr [rsp + 0x40], 0
  01c9e368  mov     r8, rdx
  01c9e36b  lea     rcx, [rsp + 0x30]
  01c9e370  lea     rdx, [rsp + 0x40]
  01c9e375  call    0x141c9e1b0  ; -> 0x1c9e1b0
  01c9e37a  mov     edx, dword ptr [rsp + 0x40]
  01c9e37e  mov     r9d, edx
  01c9e381  mov     ecx, dword ptr [rsp + 0x30]
  01c9e385  mov     r8d, ecx
  01c9e388  and     r9d, 3
  01c9e38c  je      0x141c9e3ad
  01c9e38e  mov     ecx, 4
  01c9e393  sub     ecx, r9d
  01c9e396  shl     ecx, 3
  01c9e399  shr     edx, cl
  01c9e39b  imul    eax, edx, 0xcc9e2d51
  01c9e3a1  rol     eax, 0xf
  01c9e3a4  imul    ecx, eax, 0x1b873593
  01c9e3aa  xor     ecx, r8d
  01c9e3ad  xor     ecx, ebx
  01c9e3af  mov     eax, ecx
  01c9e3b1  shr     eax, 0x10
  01c9e3b4  xor     eax, ecx
  01c9e3b6  imul    ecx, eax, 0x85ebca6b
  01c9e3bc  mov     eax, ecx
  01c9e3be  shr     eax, 0xd
  01c9e3c1  xor     eax, ecx
  01c9e3c3  imul    ecx, eax, 0xc2b2ae35
  01c9e3c9  mov     eax, ecx
  01c9e3cb  shr     eax, 0x10
  01c9e3ce  xor     eax, ecx
  01c9e3d0  add     rsp, 0x20
  01c9e3d4  pop     rbx
  01c9e3d5  ret     
