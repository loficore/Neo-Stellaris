// stellaris.exe 4.4.4 RVA 0xCCCEB0 (VA 0x140CCCEB0) — decompiled by IDA headless, session 08949c97
// NOTE: fresh IDB built from the exe on Linux; no historical Windows .i64 analysis.
// bad sp value at call has been detected, the output may be wrong!
void __fastcall sub_140CCCEB0(
        __int64 a1,
        __int64 *a2,
        __int64 *a3,
        __int64 *a4,
        __int64 *a5,
        unsigned __int64 a6,
        __int64 a7)
{
  __int64 v7; // r15
  int v8; // edi
  __int64 *v9; // r14
  __int64 (__fastcall **v10)(); // rbx
  int v11; // r12d
  __int64 v12; // r13
  bool v13; // bl
  unsigned int v14; // eax
  __int64 v15; // rsi
  __int64 v16; // rdi
  __int64 v17; // r14
  __int64 v18; // rax
  __int64 v19; // rax
  __int64 v20; // rax
  __int64 v21; // rcx
  __int64 v22; // rdi
  __int64 v23; // rax
  __int64 v24; // rdi
  unsigned int v25; // r15d
  unsigned __int128 v26; // rax
  __int64 (__fastcall *v27)(); // rdx
  __int64 *v28; // r13
  __int64 v29; // rsi
  _DWORD *v30; // r12
  __int64 v31; // rax
  __int64 v32; // r15
  __int64 v33; // rcx
  __int64 *v34; // r11
  __int64 *v35; // r10
  __int64 *v36; // r9
  __int64 *v37; // rdi
  __int64 v38; // rcx
  __int64 v39; // rcx
  __int64 v40; // rcx
  __int64 (__fastcall *v41)(_QWORD *); // rdx
  __int64 v42; // rax
  __int64 v43; // rdi
  int v44; // edx
  int v45; // ecx
  __int64 v46; // rax
  __int64 (__fastcall *v47)(_QWORD *); // rdx
  __int64 v48; // rax
  int v49; // r8d
  int v50; // edx
  __int64 v51; // r15
  int v52; // edi
  int v53; // ecx
  unsigned int v54; // eax
  __int64 v55; // rcx
  unsigned int v56; // eax
  __int64 v57; // rcx
  char v58; // di
  _QWORD v59[2]; // [rsp+100h] [rbp+0h] BYREF
  _QWORD v60[163]; // [rsp+110h] [rbp+10h] BYREF
  int v61; // [rsp+628h] [rbp+528h]
  int v62; // [rsp+62Ch] [rbp+52Ch]
  int v63; // [rsp+630h] [rbp+530h]
  int v64; // [rsp+634h] [rbp+534h]
  bool v66; // [rsp+6A8h] [rbp+5A8h] BYREF
  char v67; // [rsp+6B0h] [rbp+5B0h]
  __int64 (__fastcall **v68)(); // [rsp+6B8h] [rbp+5B8h] BYREF

  v7 = a1;
  v8 = 0;
  a6 = 25;
  v68 = off_142545CD0;
  v9 = &a7;
  a5 = &a7;
  v10 = *(__int64 (__fastcall ***)())(a1 + 4688);
  v68 = v10;
  v67 = 0;
  if ( *(_DWORD *)(*(_QWORD *)(a1 + 2040) + 812LL) )
    v66 = *(_DWORD *)(a1 + 1948) != 0;
  else
    v66 = 0;
  v11 = 0;
  if ( *(int *)(a1 + 812) <= 0 )
    goto LABEL_40;
  v12 = 0;
  v13 = v66;
  do
  {
    if ( !qword_143260FD0
      || (a3 = (__int64 *)*(unsigned int *)(*(_QWORD *)(v7 + 800) + v12),
          v14 = *(_DWORD *)(*(_QWORD *)(v7 + 800) + v12) & 0xFFFFFF,
          v14 >= *(_DWORD *)(qword_143260FD0 + 32))
      || (v15 = *(_QWORD *)(*(_QWORD *)(qword_143260FD0 + 24) + 16LL * v14 + 8)) == 0
      || *(_DWORD *)(v15 + 24) != (_DWORD)a3 )
    {
      v15 = qword_14325F9E0;
    }
    if ( (*(unsigned __int8 (__fastcall **)(__int64, __int64, __int64 *, __int64 *))(*(_QWORD *)v15 + 32LL))(
           v15,
           qword_143260FD0,
           a3,
           a4) )
    {
      if ( !(*(unsigned __int8 (__fastcall **)(__int64))(*(_QWORD *)(v15 + 64) + 800LL))(v15 + 64) )
      {
        v16 = v15 + 1104;
        v17 = (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)(v15 + 1104) + 40LL))(v15 + 1104);
        if ( !(*(unsigned __int8 (__fastcall **)(__int64))(*(_QWORD *)(v17 + 8) + 8LL))(v17 + 8) )
          v17 = (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)v16 + 16LL))(v15 + 1104);
        v18 = *(int *)(v15 + 2428);
        if ( (int)v18 < 0 || (int)v18 >= *(_DWORD *)(v17 + 44) )
          v19 = *(_QWORD *)(v17 + 32);
        else
          v19 = *(_QWORD *)(v17 + 32) + 272 * v18;
        if ( (*(_DWORD *)(*(_QWORD *)(v19 + 8) + 200LL) & 0x40000LL) != 0 )
        {
          v20 = (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)v16 + 16LL))(v15 + 1104);
          v21 = *(int *)(v15 + 2428);
          if ( (int)v21 < 0 || (int)v21 >= *(_DWORD *)(v20 + 44) )
            a2 = *(__int64 **)(v20 + 32);
          else
            a2 = (__int64 *)(*(_QWORD *)(v20 + 32) + 272 * v21);
          v22 = a2[1];
          if ( (*(_DWORD *)(v22 + 200) & 0x40000LL) != 0 && *(__int64 *)(v22 + 3192) > 0 )
          {
            v23 = (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)(v15 + 64) + 632LL))(v15 + 64);
            *(_QWORD *)(v15 + 3848) += *(_QWORD *)sub_140D150A0(v15, &v66, v23, 0);
            if ( *(_QWORD *)(v15 + 3848) >= *(_QWORD *)(v22 + 3192) && !v13 )
            {
              v24 = SHIDWORD(a6);
              if ( HIDWORD(a6) == (_DWORD)a6 )
              {
                v25 = HIDWORD(a6) + 1;
                if ( HIDWORD(a6) + 1 < (int)(float)((float)(int)a6 * 1.5) )
                  v25 = (int)(float)((float)(int)a6 * 1.5);
                v26 = v25 * (unsigned __int128)8uLL;
                if ( !is_mul_ok(v25, 8u) )
                  *(_QWORD *)&v26 = -1;
                v9 = (__int64 *)((__int64 (__fastcall *)(_QWORD, _QWORD))unk_14218525C)(v26, *((_QWORD *)&v26 + 1));
                v9[v24] = v15;
                ((void (__fastcall *)(__int64 *, __int64 *, __int64))unk_142187AC0)(v9, a5, 8 * v24);
                ((void (__fastcall *)(__int64 *, __int64 *, unsigned __int64))unk_142187AC0)(
                  &v9[v24 + 1],
                  &a5[v24],
                  (8LL * SHIDWORD(a6) - 8 * v24) & 0xFFFFFFFFFFFFFFF8uLL);
                v8 = HIDWORD(a6) + 1;
                HIDWORD(a6) = 0;
                v27 = v68[3];
                if ( (char *)v27 == (char *)sub_140156C90 )
                  sub_140156C90(&v68);
                else
                  ((void (__fastcall *)(__int64 (__fastcall ***)()))v27)(&v68);
                a5 = v9;
                a6 = __PAIR64__(v8, v25);
LABEL_37:
                v7 = a1;
                goto LABEL_38;
              }
              v33 = SHIDWORD(a6);
              a5[SHIDWORD(a6)] = v15;
              v8 = HIDWORD(a6) + 1;
              HIDWORD(a6) = v8;
              v9 = a5;
              a3 = &a5[v8];
              v34 = a3 - 1;
              v35 = &a5[v33];
              if ( v35 == a3 - 1 || v34 == a3 )
                goto LABEL_37;
              v36 = a3 - 1;
              v37 = &a5[v33];
              do
              {
                if ( v37 == --v36 )
                  break;
                a2 = v37++;
                v38 = *a2;
                *a2 = *v36;
                *v36 = v38;
              }
              while ( v37 != v36 );
              a4 = a3;
              do
              {
                if ( v34 == --a4 )
                  break;
                a2 = v34++;
                v39 = *a2;
                *a2 = *a4;
                *a4 = v39;
              }
              while ( v34 != a4 );
              for ( ; v35 != a3; *a3 = v40 )
              {
                if ( v35 == --a3 )
                  break;
                a2 = v35++;
                v40 = *a2;
                *a2 = *a3;
              }
            }
          }
        }
      }
      v7 = a1;
    }
    v8 = HIDWORD(a6);
    v9 = a5;
LABEL_38:
    ++v11;
    v12 += 4;
  }
  while ( v11 < *(_DWORD *)(v7 + 812) );
  v10 = v68;
LABEL_40:
  v28 = &v9[v8];
  if ( v9 == v28 )
    goto LABEL_100;
  while ( 2 )
  {
    v29 = *v9;
    v30 = (_DWORD *)(*v9 + 1104);
    v59[0] = off_1424B3108;
    v59[1] = *(_QWORD *)(v29 + 1112);
    sub_1401B36D0(v60, v29 + 1120);
    v60[162] = *(_QWORD *)(v29 + 2416);
    v61 = *(_DWORD *)(v29 + 2424);
    v62 = *(_DWORD *)(v29 + 2428);
    v59[0] = &off_1424B3158;
    v63 = *(_DWORD *)(v29 + 2432);
    v64 = *(_DWORD *)(v29 + 2436);
    v31 = ((__int64 (__fastcall *)(_QWORD *))unk_1402303B0)(v59);
    if ( v62 < 0 || v62 >= *(_DWORD *)(v31 + 44) )
      v32 = *(_QWORD *)(v31 + 32);
    else
      v32 = *(_QWORD *)(v31 + 32) + 272LL * v62;
    v41 = *(__int64 (__fastcall **)(_QWORD *))(v59[0] + 40LL);
    if ( (char *)v41 == (char *)&unk_140230360 )
      v42 = ((__int64 (__fastcall *)(_QWORD *))unk_140230360)(v59);
    else
      v42 = v41(v59);
    v43 = v42;
    if ( (*(unsigned __int8 (__fastcall **)(__int64))(*(_QWORD *)(v42 + 8) + 8LL))(v42 + 8) )
    {
      v44 = *(_DWORD *)(v43 + 44);
      v45 = v62 + 1;
      if ( v44 <= v62 + 1 )
      {
        if ( v62 < 0 || v62 >= v44 )
          goto LABEL_65;
        v46 = *(_QWORD *)(v43 + 32) + 272LL * v62;
      }
      else
      {
        if ( v45 >= 0 )
        {
          v46 = *(_QWORD *)(v43 + 32) + 272LL * v45;
          goto LABEL_79;
        }
LABEL_65:
        v46 = *(_QWORD *)(v43 + 32);
      }
    }
    else
    {
      v47 = *(__int64 (__fastcall **)(_QWORD *))(v59[0] + 16LL);
      if ( (char *)v47 == (char *)&unk_1402303B0 )
        v48 = ((__int64 (__fastcall *)(_QWORD *))unk_1402303B0)(v59);
      else
        v48 = v47(v59);
      v49 = *(_DWORD *)(v48 + 44);
      v50 = v62 + 1;
      if ( v49 <= v62 + 1 )
      {
        if ( v62 >= 0 && v62 < v49 )
        {
          v46 = *(_QWORD *)(v48 + 32) + 272LL * v62;
          goto LABEL_79;
        }
      }
      else if ( v50 >= 0 )
      {
        v46 = *(_QWORD *)(v48 + 32) + 272LL * v50;
        goto LABEL_79;
      }
      v46 = *(_QWORD *)(v48 + 32);
    }
LABEL_79:
    if ( v46 == v32 )
    {
      v51 = a1;
      v58 = v67;
    }
    else
    {
      v10 = (__int64 (__fastcall **)())((char *)v10
                                      + *(_QWORD *)(*(_QWORD *)(v46 + 8) + 1648LL)
                                      - *(_QWORD *)(*(_QWORD *)(v32 + 8) + 1648LL));
      v51 = a1;
      sub_140CE6580(a1, v10);
      v52 = v30[331];
      v53 = *(_DWORD *)((*(__int64 (__fastcall **)(_DWORD *))(*(_QWORD *)v30 + 16LL))(v30) + 44) - 1;
      if ( v30[331] + 1 < v53 )
        v53 = v30[331] + 1;
      v30[331] = v53;
      if ( v52 != v53 )
        sub_140D419B0(v30);
      *(_QWORD *)(v29 + 3848) = 0;
      sub_140D20D50(v29, v30);
      (*(void (__fastcall **)(__int64))(*(_QWORD *)(v29 + 64) + 152LL))(v29 + 64);
      (*(void (__fastcall **)(__int64))(*(_QWORD *)(v29 + 64) + 632LL))(v29 + 64);
      if ( !qword_14325EF00
        || (v54 = *(_DWORD *)(v29 + 2448) & 0xFFFFFF, v54 >= *(_DWORD *)(qword_14325EF00 + 32))
        || (v55 = *(_QWORD *)(*(_QWORD *)(qword_14325EF00 + 24) + 16LL * v54 + 8)) == 0
        || *(_DWORD *)(v55 + 48) != *(_DWORD *)(v29 + 2448) )
      {
        v55 = qword_14325FA20;
      }
      *(_DWORD *)(v55 + 4672) |= 0x20000000u;
      sub_140CD97A0(v55, 0);
      if ( !qword_1432610A8
        || (v56 = *(_DWORD *)(v51 + 976) & 0xFFFFFF, v56 >= *(_DWORD *)(qword_1432610A8 + 32))
        || (v57 = *(_QWORD *)(*(_QWORD *)(qword_1432610A8 + 24) + 16LL * v56 + 8)) == 0
        || *(_DWORD *)(v57 + 8) != *(_DWORD *)(v51 + 976) )
      {
        v57 = qword_14325FA48;
      }
      sub_140E8BB00(v57, v59, v30);
      v58 = 1;
      v67 = 1;
    }
    sub_1401B3A40(v60);
    if ( ++v9 != v28 )
      continue;
    break;
  }
  if ( v58 )
    sub_140CD91B0(v51);
  v9 = a5;
LABEL_100:
  v68 = off_142545CD0;
  HIDWORD(a6) = 0;
  if ( v9 != &a7 )
  {
    if ( v9 )
      ((void (__fastcall *)(__int64 *, __int64 *, __int64 *, __int64 *))unk_142185254)(v9, a2, a3, a4);
  }
}
