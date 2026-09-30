// stellaris.exe 4.4.4 RVA 0xD150A0 (VA 0x140D150A0) — IDA headless session 08949c97
// fresh IDB from the Linux exe copy; rebuilt function item + flushed hexrays cache before decompile
void __fastcall sub_140D150A0(__int64 a1, _QWORD *a2, __int64 a3, __int64 a4)
{
  _DWORD *v7; // r14
  unsigned int v8; // eax
  __int64 v9; // rax
  int v10; // eax
  __int64 v11; // rbx
  __int64 v12; // rax
  __int64 v13; // r8
  __int64 v14; // rax
  __int128 v15; // xmm2
  __int64 v16; // r8
  char *v17; // rdx
  __int64 v18; // rcx
  __int64 v19; // r8
  const char *v20; // [rsp+30h] [rbp-58h] BYREF
  int v21; // [rsp+38h] [rbp-50h]
  char v22; // [rsp+3Ch] [rbp-4Ch]
  _BYTE v23[16]; // [rsp+40h] [rbp-48h] BYREF
  int v24; // [rsp+50h] [rbp-38h] BYREF
  __int128 v25; // [rsp+58h] [rbp-30h] BYREF
  __m128i si128; // [rsp+70h] [rbp-18h]

  v7 = (_DWORD *)(a1 + 1104);
  if ( !qword_14325EF00
    || (v8 = *(_DWORD *)(a1 + 2448) & 0xFFFFFF, v8 >= *(_DWORD *)(qword_14325EF00 + 32))
    || (v9 = *(_QWORD *)(*(_QWORD *)(qword_14325EF00 + 24) + 16LL * v8 + 8)) == 0
    || *(_DWORD *)(v9 + 48) != *(_DWORD *)(a1 + 2448) )
  {
    v9 = qword_14325FA20;
  }
  v10 = *(_DWORD *)(v9 + 1076);
  if ( !qword_143260FD8
    || (v10 & 0xFFFFFFu) >= *(_DWORD *)(qword_143260FD8 + 32)
    || (v11 = *(_QWORD *)(*(_QWORD *)(qword_143260FD8 + 24) + 16LL * (v10 & 0xFFFFFF) + 8)) == 0
    || *(_DWORD *)(v11 + 32) != v10 )
  {
    v11 = qword_14325F390;
  }
  v12 = (*(__int64 (__fastcall **)(_DWORD *))(*(_QWORD *)v7 + 16LL))(v7);
  v13 = (unsigned int)(v7[331] + 1);
  if ( *(_DWORD *)(v12 + 44) <= (int)v13 )
  {
    if ( a4 )
    {
      sub_14030F380(a4, 1);
      v20 = "BIOSHIP_NO_GROWTH_UPGRADE";
      v21 = 25;
      v22 = 0;
      v14 = sub_141CEFEB0(v23, &v20, 0, 0);
      v15 = *(_OWORD *)v14;
      v16 = *(int *)(v14 + 8);
      v24 = 0;
      v25 = 0;
      si128 = _mm_load_si128(xmmword_142702670);
      BYTE8(v25) = 0;
      sub_14015F770(&v24, v15, v16);
      sub_141CEFD70(v23);
      v17 = (char *)&v25 + 8;
      if ( si128.m128i_i64[1] >= 0x10uLL )
        v17 = (char *)*((_QWORD *)&v25 + 1);
      sub_141C89700(a4, v17, si128.m128i_i64[0]);
      if ( si128.m128i_i64[1] >= 0x10uLL && v24 != 1 )
      {
        ((void (__fastcall *)(_QWORD))unk_141CC4450)(*((_QWORD *)&v25 + 1));
        *a2 = 0;
        return;
      }
    }
    goto LABEL_19;
  }
  if ( !(unsigned __int8)sub_140E87EF0(v12, v11, v13, a4) )
  {
LABEL_19:
    *a2 = 0;
    return;
  }
  sub_140E88500(v18, a2, v19, a3, a4);
}
