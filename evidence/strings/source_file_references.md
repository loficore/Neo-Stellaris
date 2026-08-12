# Source File String References

Binary: `stellaris.exe` (Clausewitz engine "augustus")
Session: `cdd1c2bb`
Date: 2026-08-11
Purpose: Map 6 source file path strings (`.rdata`) to the functions that reference them, validating key addresses in AGENTS.md.

## Summary Table

| String (basename) | String Address | Full Content | Xref Count | Primary Referencing Functions |
|---|---|---|---|---|
| `effect_impl.cpp` | `0x14260ee30` | `C:\mnt\gsg\stellaris\augustus\augustus\source\effect_impl\effect_impl.cpp` | 363 | `sub_14180B050` (effect dispatch switch-case), 140+ effect executors |
| `scriptedeffect.cpp` | `0x14253bb70` | `C:\mnt\gsg\stellaris\augustus\augustus\source\scriptedeffect.cpp` | 1 | `sub_1408A6EB0` (scripted effect template registration) |
| `scriptedtrigger.cpp` | `0x14253bc60` | `C:\mnt\gsg\stellaris\augustus\augustus\source\scriptedtrigger.cpp` | 1 | `sub_1408A79A0` (scripted trigger template registration) |
| `eventcommands.cpp` | `0x142548290` | `C:\mnt\gsg\stellaris\augustus\augustus\source\eventcommands.cpp` | 6 | `sub_1409FCE90` (event command handler), `sub_1409FDB60`, `sub_1409FDD20` |
| `eventmanager.cpp` | `0x142511938` | `C:\mnt\gsg\stellaris\augustus\augustus\source\eventmanager.cpp` | 24 | `sub_140402B80` (event manager), `sub_140404EB0`, `sub_1405CD6B0` |
| `game_singleobjectdatabase.h` | `0x1424d7c30` | `C:\mnt\gsg\stellaris\augustus\augustus\source\game_singleobjectdatabase.h` | 166 | 130+ database registration/ctor functions |

**All 6 string addresses match AGENTS.md exactly.** All xrefs are `data` type (string address loaded via `lea` for error/assert paths), confirming the `.rdata` segment placement.

---

## 1. `effect_impl.cpp` @ `0x14260ee30`

Full string: `C:\mnt\gsg\stellaris\augustus\augustus\source\effect_impl\effect_impl.cpp`

363 xrefs — this is the effect implementation core. The string is used as the
`__FILE__` argument for error/assert reporting in every effect's execute path.
**Key finding: `sub_14180B050` (AGENTS.md "Effect dispatch switch-case", 254+159+166 cases)
references it at `0x14180B4B1` and `0x14180B5B6`.**

First-200 xrefs — unique referencing functions (representative subset of ~140):
`sub_14180B050` (dispatch switch-case, x2), `sub_14180B8D0` (x3), `sub_14180BB80`,
`sub_14180C420`, `sub_14180DCC0`, `sub_14180EAD0` (x2), `sub_14180F270`, `sub_1418102A0`,
`sub_141810590`, `sub_141810B00`, `sub_1418111A0`, `sub_141811C40` (x2), `sub_141812FE0`,
`sub_141814F90`, `sub_141815F70`, `sub_141816C00`, `sub_141817900`, `sub_141818020`,
`sub_141818290` (x2), `sub_1418186F0`, `sub_141818800`, `sub_141818B70` (x2), `sub_141818D00`,
`sub_141818E00`, `sub_141819350`, `sub_141819EE0`, `sub_14181AD10` (x3), `sub_14181B740` (x6),
`sub_14181DD60`, `sub_14181EEB0`, `sub_14181F540`, `sub_14181F5B0` (x2), `sub_14181FAC0`,
`sub_14181FB30`, `sub_141820320` (x3), `sub_1418211C0`, `sub_141821310` (x4), `sub_141822D60`,
`sub_141822E20` (x10), `sub_141825530`, `sub_141825C40`, `sub_141825DF0`, `sub_1418267D0`,
`sub_1418275D0`, `sub_141827F70`, `sub_141828E60` (x3), `sub_14182B8D0` (x3), `sub_14182C2A0`,
`sub_1418315F0`, `sub_141831770`, `sub_141831CE0`, `sub_141832560`, `sub_1418327E0`,
`sub_1418341B0`, `sub_141836110`, `sub_141836210` (x3), `sub_141837380`, `sub_1418375E0` (x2),
`sub_141838010`, `sub_141838730` (x2), `sub_141838A90`, `sub_141839EB0`, `sub_14183A300`,
`sub_14183AB50` (x2), `sub_14183AE70` (x3), `sub_14183B7A0`, `sub_14183CD50` (x6),
`sub_14183EBA0`, `sub_14183F6E0`, `sub_141842710`, `sub_141843530` (x2), `sub_141843B10`,
`sub_141843C30` (x3), `sub_1418462C0`, `sub_141846870` (x3), `sub_141846CA0` (x2),
`sub_141848560` (x2), `sub_141848AF0`, `sub_1418490E0`, `sub_141849160` (x2), `sub_14184A090`,
`sub_14184ACA0`, `sub_14184B0D0`, `sub_14184B400`, `sub_14184B5D0` (x2), `sub_14184C180`,
`sub_14184C250`, `sub_14184C320`, `sub_14184C790`, `sub_14184CBF0`, `sub_14184CD00`,
`sub_14184D250`, `sub_14184D660` (x2), `sub_14184FE30`, `sub_141850380`, `sub_141850510`,
`sub_141853550`, `sub_141853D10` (x2), `sub_141854700`, `sub_141854780`, `sub_141854BA0`,
`sub_141855560`, `sub_141855B80`, `sub_141856000`, `sub_141856DF0`, `sub_141857AB0`,
`sub_141858460`, `sub_141858BD0`, `sub_141858CC0` (x2), `sub_141859650`, `sub_141859F80`,
`sub_14185A820`, `sub_14185ADD0`, `sub_14185AF10`, `sub_14185C140` (x2), `sub_14185C810`,
`sub_14185C990` (x5), `sub_14185EDB0`, `sub_14185EEA0`, `sub_14185F3E0` (x2), `sub_14185F8F0` (x2),
`sub_141860790`, `sub_1418622C0`, `sub_1418637E0`, `sub_141863860`, `sub_141863C10`,
`sub_141863C90` (x3), `sub_1418649F0`, `sub_141864C00`, `sub_1418653F0` (x3)

Remaining 163 xref sites (addresses only, offset 200-363): `0x141865d8f` through `0x14193d810`.

---

## 2. `scriptedeffect.cpp` @ `0x14253bb70`

Full string: `C:\mnt\gsg\stellaris\augustus\augustus\source\scriptedeffect.cpp`

Single xref — matches AGENTS.md `sub_1408A6EB0` (scripted effect template registration to BST at `qword_14339AEA8`):

| Xref Site | Type | Function | Function Size |
|---|---|---|---|
| `0x1408A7027` | data | `sub_1408A6EB0` | `0x1c9` |

---

## 3. `scriptedtrigger.cpp` @ `0x14253bc60`

Full string: `C:\mnt\gsg\stellaris\augustus\augustus\source\scriptedtrigger.cpp`

Single xref — matches AGENTS.md `sub_1408A79A0` (scripted trigger template registration to BST at `qword_143287968`):

| Xref Site | Type | Function | Function Size |
|---|---|---|---|
| `0x1408A7B17` | data | `sub_1408A79A0` | `0x1c9` |

---

## 4. `eventcommands.cpp` @ `0x142548290`

Full string: `C:\mnt\gsg\stellaris\augustus\augustus\source\eventcommands.cpp`

6 xrefs — matches AGENTS.md `sub_1409FCE90` (event command handler):

| Xref Site | Type | Function | Function Size |
|---|---|---|---|
| `0x1409FD037` | data | `sub_1409FCE90` | `0x8d5` |
| `0x1409FD3F0` | data | `sub_1409FCE90` | `0x8d5` |
| `0x1409FDBEB` | data | `sub_1409FDB60` | `0x12a` |
| `0x1409FDC64` | data | `sub_1409FDB60` | `0x12a` |
| `0x1409FDDFA` | data | `sub_1409FDD20` | `0x52d` |
| `0x1409FDF71` | data | `sub_1409FDD20` | `0x52d` |

---

## 5. `eventmanager.cpp` @ `0x142511938`

Full string: `C:\mnt\gsg\stellaris\augustus\augustus\source\eventmanager.cpp`

24 xrefs — event manager pipeline functions:

| Xref Sites | Function | Function Size | Site Count |
|---|---|---|---|
| `0x140402EDC` `0x1404032ED` `0x1404033AB` `0x140403453` `0x140403862` `0x140403967` `0x140403A7C` | `sub_140402B80` | `0x1058` | 7 |
| `0x140403DEA` | `sub_140403BE0` | `0x30a` | 1 |
| `0x140404A09` | `sub_1404046B0` | `0x7fa` | 1 |
| `0x140404FD2` `0x14040514D` `0x1404053E5` `0x14040556B` `0x14040561C` `0x1404059AD` `0x140405B46` `0x140405D35` `0x140405DEE` `0x14040612A`... | `sub_140404EB0` | `0x1239` | 11 |
| `0x140406A0C` | `sub_1404069F0` | `0x201` | 1 |
| `0x140406C6C` | `sub_140406C00` | `0x228` | 1 |
| `0x1405CDDE3` `0x1405CE4CE` | `sub_1405CD6B0` | `0x11c2` | 2 |
| `0x140F44038` | `sub_140F43EA0` | `0x3a0` | 1 |

---

## 6. `game_singleobjectdatabase.h` @ `0x1424d7c30`

Full string: `C:\mnt\gsg\stellaris\augustus\augustus\source\game_singleobjectdatabase.h`

166 xrefs — this is the database template base header (`CSingleObjectDatabase`); referenced by
130+ database constructor/registration functions. Matches AGENTS.md database template base
string. Notable nearby references include `sub_1408A7300` / `sub_1408A7DF0` (database plumbing
adjacent to the scripted effect/trigger registration functions at `0x1408A6EB0`/`0x1408A79A0`).

Unique referencing functions (representative, 166 total xrefs):
`sub_140207330`, `sub_140207ED0`, `sub_140208410`, `sub_140208B00`, `sub_140209040`,
`sub_14020B430`, `sub_14020BA80`, `sub_14020EB20`, `sub_14020F070`, `sub_14020F640`,
`sub_140210B30`, `sub_140213E40`, `sub_140215260`, `sub_140218340`, `sub_140218830`,
`sub_1402198B0`, `sub_14021A040`, `sub_1403AAEB0`, `sub_1403AB900`, `sub_1403AC220`,
`sub_1403ACB40`, `sub_1403AD590`, `sub_1403ADFE0`, `sub_1403AEA30`, `sub_1403AF480`,
`sub_1403AFED0`, `sub_1403BB3D0`, `sub_1403BCB70`, `sub_1404143E0`, `sub_140418570`,
`sub_14041E0E0`, `sub_140429AB0`, `sub_1404349A0`, `sub_14043F500`, `sub_140447940`,
`sub_14044D8E0`, `sub_14044F050`, `sub_14044FE30`, `sub_140454700`, `sub_140454810`,
`sub_14045B650`, `sub_14045BCC0`, `sub_1404603B0`, `sub_140464A80`, `sub_140468D80`,
`sub_140469770`, `sub_14046A1F0`, `sub_140475220`, `sub_140475AF0`, `sub_140477070`,
`sub_14047BA30`, `sub_14047BD00`, `sub_140492E40`, `sub_1404A0620`, `sub_1404A4290`,
`sub_1404B2D30`, `sub_1404B9FA0`, `sub_1404BA2F0`, `sub_1404C91C0`, `sub_1404CCCE0`,
`sub_1404D1E40`, `sub_1404D9EA0`, `sub_1404DCDB0`, `sub_1404E5D00`, `sub_1404EF050`,
`sub_1404EF3F0`, `sub_1404EF790`, `sub_1404F4D30`, `sub_1404F8B50`, `sub_14050E610`,
`sub_14052DF20`, `sub_14053EBE0`, `sub_140544C40`, `sub_140546D30`, `sub_140554070`,
`sub_140559DE0`, `sub_1405628B0`, `sub_140566950`, `sub_140568A50`, `sub_14056AD10`,
`sub_14056D7A0`, `sub_140570260`, `sub_140573800`, `sub_1405750F0`, `sub_140576790`,
`sub_140578C60`, `sub_14057B760`, `sub_14057EC50`, `sub_140583CA0`, `sub_140584F80`,
`sub_14058A480`, `sub_14058A870`, `sub_14058C220`, `sub_140593440`, `sub_140599730`,
`sub_14059C9C0`, `sub_14059CD10`, `sub_14059EB60`, `sub_1405ABAA0`, `sub_1405ABBA0`,
`sub_1405AD680`, `sub_1405B2480`, `sub_1405B4C00`, `sub_1405B7A70`, `sub_1405B7DC0`,
`sub_1405BC3F0`, `sub_1405C0840`, `sub_1405C2640`, `sub_1405C6260`, `sub_1405C76E0`,
`sub_1405C8E40`, `sub_1405D4CD0`, `sub_1405D8420`, `sub_140667900`, `sub_1406E22C0`,
`sub_1406F60F0`, `sub_1407D69E0`, `sub_1407EECF0`, `sub_1407F85D0`, `sub_1407F86D0`,
`sub_140810920`, `sub_140810A30`, `sub_140811CC0`, `sub_140813E50`, `sub_140815FC0`,
`sub_1408163E0`, `sub_1408191E0`, `sub_14083AA80`, `sub_14083B4D0`, `sub_14087EA10`,
`sub_140898F70`, `sub_14089C880`, `sub_14089D980`, `sub_14089E820`, `sub_14089FA10`,
`sub_1408A0DF0`, `sub_1408A5F00`, `sub_1408A7300`, `sub_1408A7DF0`, `sub_1408A9600`,
`sub_1408AA7B0`, `sub_1408AB510`, `sub_1408AC950`, `sub_1408FF5C0`, `sub_140908360`,
`sub_14090A2E0`, `sub_14090AF90`, `sub_14090E8E0`, `sub_140BA94C0`, `sub_140BABA80`,
`sub_140BABB90`, `sub_140BAE520`, `sub_140BC4840`, `sub_140DA2B50`, `sub_140DAFEF0`,
`sub_140DB2210`, `sub_140DB9E20`, `sub_140DD2620`, `sub_140DD53F0`, `sub_140F9D450`,
`sub_140FAD200`, `sub_140FAEDE0`, `sub_140FB34C0`, `sub_1417848F0`, `sub_141785A60`,
`sub_141785F70`

---

## Conclusions

1. **All 6 AGENTS.md string addresses are confirmed** with zero deviation.
2. **AGENTS.md key functions confirmed via xrefs:**
   - `sub_14180B050` (effect dispatch switch-case) ← `effect_impl.cpp`
   - `sub_1408A6EB0` (scripted effect registration) ← `scriptedeffect.cpp`
   - `sub_1408A79A0` (scripted trigger registration) ← `scriptedtrigger.cpp`
   - `sub_1409FCE90` (event command handler) ← `eventcommands.cpp`
3. **New findings:**
   - `effect_impl.cpp` string has 363 xrefs — it is the `__FILE__` arg for assert/error in
     essentially every effect executor. This means the whole `0x14180xxxx` block is the effect
     implementation surface area, not just the dispatcher.
   - `eventcommands.cpp` has two additional handler functions (`sub_1409FDB60`, `sub_1409FDD20`)
     not in AGENTS.md.
   - `eventmanager.cpp` block is `sub_140402B80`+ (event manager) with 24 string refs.
   - `game_singleobjectdatabase.h` is referenced by 166 sites / 130+ functions — confirms the
     `CSingleObjectDatabase` template is the base for essentially all game databases.
