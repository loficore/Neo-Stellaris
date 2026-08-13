# Version Compatibility

Supported Stellaris versions and engine compatibility information.

## Supported Versions

| Stellaris Version | Status | Notes |
|-------------------|--------|-------|
| 3.x (3.0–3.14) | Partial | Offsets verified from IDA for 3.x series |
| 4.0+ | Not tested | Requires offset re-verification |

**Current target:** Stellaris 3.x (codename "augustus")

## Engine Version

The Clausewitz engine version is identified by:
- **Binary:** `stellaris.exe`
- **Codename:** "augustus"
- **Architecture:** x86_64 (Windows PE)
- **Runtime:** Custom allocator, no libc dependency

## Verified Offsets

All offsets are derived from IDA reverse engineering of the 3.x binary. They are stored in `src/dll/shared/offsets.zig`.

### CEffect Object Layout

| Offset | Field | Type | Description |
|--------|-------|------|-------------|
| +0x038 (56) | Effect name | SSO string | Small String Optimization (≤22 bytes inline) |
| +0xFF0 (4080) | Effect ID | i32 | Used for dispatch in main effect switch |
| +0x6A8 (1704) | Vtable pointer | ptr | Virtual function table |

### CEventScope Layout

| Offset | Field | Type | Description |
|--------|-------|------|-------------|
| +8 | Scope type | i64 | Bit flag (power of 2) |
| +16 | Object ID | i64 | Game object identifier |

### CTrigger Object Layout

| Offset | Field | Type | Description |
|--------|-------|------|-------------|
| +0x038 (56) | Trigger name | SSO string | Small String Optimization |
| +0xFF0 (4080) | Trigger ID | i32 | Trigger identifier |
| +0x6A8 (1704) | Vtable pointer | ptr | Virtual function table |

### Hook Addresses

| Function | Address | Purpose |
|----------|---------|---------|
| `CEffect::ExecuteActual` | `0x14181B740` | Effect execution hook target |
| `CTrigger::Evaluate` | `0x1408A6F20` | Trigger evaluation hook target |

### Global Data Addresses

| Address | Name | Purpose |
|---------|------|---------|
| `0x143287360` | GameState | Main game state object |
| `0x143287788` | CountryDB | Country database |
| `0x14339AEA8` | ScriptedEffectDB | Scripted effect templates |
| `0x143287968` | ScriptedTriggerDB | Scripted trigger templates |
| `0x14339AFE8` | EventDB | Event database |

## Scripted Effect/Trigger Threshold

| Threshold | Value | Description |
|-----------|-------|-------------|
| `SCRIPTED_EFFECT_BASE` | 4081 | First custom/scripted effect ID |
| Vanilla effects | ≤ 4081 | Pass through to engine |
| Custom effects | > 4081 | Routed to JavaScript handlers |

## DLL Compatibility

### Build Requirements

| Requirement | Version |
|-------------|---------|
| Zig compiler | ≥ 0.16.0 |
| Target | x86_64-windows |
| Output | `stellaris_quickjs.dll` (dynamic library) |

### Injection Method

The DLL exports two functions:

1. **`DllMain`** — Standard Windows DLL entry point
2. **`PushCApplicationPtr(ptr)`** — Called by the C++ loader after injection to pass the engine pointer

The DLL must be injected using a DLL injector that supports calling exported functions after load.

### Memory Model

- The DLL uses page-aligned memory allocation for trampolines
- Memory protection changes use `VirtualProtect` (RX↔RWX)
- Instruction cache is flushed after code patching
- Trampoline memory is allocated near the target function (within ±2GB for rel32 compatibility)

## Version Update Process

When a new Stellaris version is released:

1. **Dump the new binary** — Open `stellaris.exe` in IDA Pro
2. **Verify offsets** — Check that CEffect/CEventScope/CTrigger layouts haven't changed
3. **Verify hook addresses** — Confirm `CEffect::ExecuteActual` and `CTrigger::Evaluate` addresses
4. **Verify global addresses** — Check GameState, CountryDB, and other global pointers
5. **Update offsets.zig** — Modify the offset constants
6. **Run tests** — Ensure all unit tests pass
7. **Test in-game** — Verify effects/triggers fire correctly

### Common Changes Between Versions

| Change Type | Impact | Mitigation |
|-------------|--------|------------|
| Object layout shift | Breaks field reads | Update offsets in `offsets.zig` |
| Hook address change | Breaks detour installation | Update addresses in `ceffect.zig`/`ctrigger.zig` |
| Global address change | Breaks game state reads | Update addresses in `gamestate.zig` |
| New effect IDs | May conflict with custom IDs | Adjust `SCRIPTED_EFFECT_BASE` if needed |
| Vtable changes | Breaks virtual calls | Re-analyze vtable layout in IDA |

## Cross-Platform Notes

| Platform | Status | Notes |
|----------|--------|-------|
| Windows x86_64 | Supported | Primary target |
| Linux x86_64 | Not supported | Requires Wine/Proton; DLL injection differs |
| macOS | Not supported | No native Clausewitz builds |

The build system defaults to x86_64-windows. Cross-compilation to other targets is possible but not officially supported.

## Testing Compatibility

```bash
# Run all tests to verify offset consistency
zig build test

# Tests verify:
# - Offset values match expected constants
# - Scope types are power-of-2 bit flags
# - Effect IDs are within valid ranges
# - SSO string layout matches engine
# - x86_64 instruction decoding is correct
```

## Future Compatibility

Planned work to improve version compatibility:

- [ ] Dynamic offset detection (scan for patterns instead of hardcoding)
- [ ] Version-specific offset profiles
- [ ] Runtime offset validation
- [ ] Automatic offset discovery via signature scanning
