// stellaris.exe 4.4.4 RVA 0xE88500 (VA 0x140E88500), size 716 after func rebuild
// IDA headless session f3ea6101. EVIDENCE THAT THIS IS NOT KEYWORD REGISTRATION:
// it manipulates BIOSHIP_GROWTH_PROGRESS and item ids 543/544 (see string lits below).
_QWORD *__fastcall sub_140E88500(__int128 *a1, _QWORD *a2, __int64 a3, __int64 a4, __int64 a5)
{
  int v6; // eax
  int v7; // edx
  __int64 v8; // rdx
  __int64 v9; // rax
  __int64 v10; // r9
  __int64 v11; // rbx
  char *v12; // rdx
  char v14; // [rsp+20h] [rbp-E0h]
  const char *v15; // [rsp+30h] [rbp-D0h] BYREF
  int v16; // [rsp+38h] [rbp-C8h]
  char v17; // [rsp+3Ch] [rbp-C4h]
  __int128 v18; // [rsp+40h] [rbp-C0h]
  __int64 v19; // [rsp+50h] [rbp-B0h] BYREF
  int v20; // [rsp+58h] [rbp-A8h]
  __int128 v21; // [rsp+60h] [rbp-A0h] BYREF
  __int128 v22; // [rsp+70h] [rbp-90h]
  __int128 v23; // [rsp+80h] [rbp-80h]
  int v24; // [rsp+90h] [rbp-70h] BYREF
  __int128 v25; // [rsp+98h] [rbp-68h] BYREF
  __m128i si128; // [rsp+B0h] [rbp-50h]
  _DWORD v27[4]; // [rsp+C0h] [rbp-40h] BYREF
  __int64 v28; // [rsp+D0h] [rbp-30h]
  unsigned __int64 v29; // [rsp+E8h] [rbp-18h]
  int v30; // [rsp+F0h] [rbp-10h] BYREF
  __int128 v31; // [rsp+F8h] [rbp-8h]
  _BYTE v32[72]; // [rsp+138h] [rbp+38h] BYREF
  __int128 *v33; // [rsp+1A0h] [rbp+A0h] BYREF
  int v34; // [rsp+1B0h] [rbp+B0h]
  int v35; // [rsp+1B4h] [rbp+B4h]

  v35 = HIDWORD(a3);
  v33 = a1;
  v34 = 0;
  *a2 = qword_1433720E8;
  v6 = 0;
  v7 = *(_DWORD *)(a4 + 28);
  if ( v7 <= 0 )
    goto LABEL_4;
  while ( *(_DWORD *)(*(_QWORD *)(a4 + 16) + 4LL * v6) != 543 )
  {
    if ( ++v6 >= v7 )
      goto LABEL_4;
  }
  v8 = *(_QWORD *)(*(_QWORD *)(a4 + 56) + 16LL * v6);
  if ( (*(_DWORD *)(qword_142979760 + 95736) & 0x20) != 0 )
  {
    if ( v8 >= 0 )
    {
      if ( v8 > 100000 )
        v8 = 100000;
      goto LABEL_5;
    }
LABEL_4:
    v8 = 0;
  }
LABEL_5:
  v9 = 0;
  if ( v8 > 0 )
    v9 = v8;
  *a2 += v9;
  v14 = 0;
  sub_140372340(&v33, a2, a4, 544, v14);
  if ( a5 )
  {
    sub_14030F380(a5, 1);
    LOBYTE(v10) = 1;
    v11 = sub_141CFC400(v27, *a2, 2, v10);
    v15 = "BIOSHIP_GROWTH_PROGRESS";
    v16 = 23;
    v17 = 0;
    sub_142185924(&v30, 144, 1, &unk_14023E550, sub_14023E5A0);
    *(_QWORD *)&v18 = "VALUE";
    DWORD2(v18) = 5;
    BYTE12(v18) = 0;
    v21 = *(_OWORD *)v11;
    v22 = *(_OWORD *)(v11 + 16);
    v23 = *(_OWORD *)(v11 + 32);
    *(_QWORD *)(v11 + 32) = 0;
    *(_QWORD *)(v11 + 40) = 15;
    *(_BYTE *)(v11 + 16) = 0;
    v33 = &v21;
    v31 = v18;
    v30 = 1;
    sub_14015EA40(v32, &v21);
    if ( *((_QWORD *)&v23 + 1) >= 0x10u && (_DWORD)v21 != 1 )
      ((void (__fastcall *)(_QWORD))unk_141CC4450)(v22);
    *(_QWORD *)&v23 = 0;
    *((_QWORD *)&v23 + 1) = 15;
    LOBYTE(v22) = 0;
    sub_141CEFEB0(&v19, &v15, &v30, 1);
    v34 = 6;
    sub_142185264(&v30, 144, 1, sub_14023E5A0);
    v24 = 0;
    v25 = 0;
    si128 = _mm_load_si128(xmmword_142702670);
    BYTE8(v25) = 0;
    sub_14015F770(&v24, v19, v20);
    sub_141CEFD70(&v19);
    v12 = (char *)&v25 + 8;
    if ( si128.m128i_i64[1] >= 0x10uLL )
      v12 = (char *)*((_QWORD *)&v25 + 1);
    sub_141C89700(a5, v12, si128.m128i_i64[0]);
    if ( si128.m128i_i64[1] >= 0x10uLL && v24 != 1 )
      ((void (__fastcall *)(_QWORD))unk_141CC4450)(*((_QWORD *)&v25 + 1));
    if ( v29 >= 0x10 && v27[0] != 1 )
      ((void (__fastcall *)(__int64))unk_141CC4450)(v28);
  }
  return a2;
}
