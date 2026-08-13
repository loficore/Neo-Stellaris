# Integration Tests — stellaris_quickjs DLL

Manual integration tests for verifying the DLL works correctly with the Stellaris game.

## Prerequisites

- Windows 10/11 (x86_64)
- Stellaris installed via Steam (any recent version)
- Administrator privileges (required for DLL injection)
- `stellaris_quickjs.dll` built via `zig build`
- `stellaris-loader.exe` built from `src/loader/`

## Directory Structure

```
tests/integration/
├── README.md                  # This file
├── TEST_SCENARIOS.md          # Detailed test procedures
├── run_tests.ps1              # PowerShell test runner
├── verify_dll.bat             # DLL verification script
├── test_mod/                  # Test mod for Stellaris
│   ├── descriptor.mod         # Mod descriptor
│   ├── common/
│   │   ├── scripted_effects/
│   │   │   └── test_effects.txt
│   │   ├── scripted_triggers/
│   │   │   └── test_triggers.txt
│   │   ├── scripted_loc/
│   │   │   └── test_text.txt
│   │   └── button_effects/
│   │       └── test_buttons.txt
│   ├── events/
│   │   └── test_events.txt
│   └── interface/
│       └── test_window.gui
├── scripts/
│   └── test.js                # JavaScript test file
└── evidence/                  # Test results and logs
```

## Quick Start

### 1. Build the DLL

```bash
# From project root
zig build
```

### 2. Install Test Mod

Copy `test_mod/` to Stellaris mod directory:
```
%USERPROFILE%\Documents\Paradox Interactive\Stellaris\mod\stellaris_quickjs_test/
```

Or use the test runner:
```powershell
.\run_tests.ps1 -InstallMod
```

### 3. Run Tests

```powershell
# Full test suite
.\run_tests.ps1

# Individual test
.\run_tests.ps1 -Test "DLL Injection"

# Install mod only
.\run_tests.ps1 -InstallMod
```

### 4. Verify DLL Exports

```batch
verify_dll.bat
```

## Test Scenarios Overview

| # | Test | Description | Pass Criteria |
|---|------|-------------|---------------|
| T1 | DLL Injection | Inject DLL into Stellaris process | PushCApplicationPtr called successfully |
| T2 | QuickJS Execution | Execute JavaScript in game context | JS code runs without errors |
| T3 | Effect Hook | Register and trigger custom effect | JS handler called when effect executes |
| T4 | Trigger Hook | Register and evaluate custom trigger | JS handler returns correct boolean |
| T5 | UI Integration | Display custom .gui window | Window appears in game |

## Manual QA Checklist

- [ ] DLL builds without errors
- [ ] Loader finds stellaris.exe process
- [ ] DLL injects successfully (check console output)
- [ ] PushCApplicationPtr is called with valid pointer
- [ ] QuickJS runtime initializes (check log output)
- [ ] Test mod loads in Stellaris launcher
- [ ] Test effects execute in game
- [ ] Test triggers evaluate correctly
- [ ] Custom UI window appears
- [ ] Button clicks trigger JS callbacks
- [ ] No crashes or hangs during tests
- [ ] DLL unloads cleanly on game exit

## Troubleshooting

### "stellaris.exe not found"
- Ensure Stellaris is running before injection
- Check Task Manager for the process name

### "Access denied"
- Run loader as Administrator
- Check antivirus isn't blocking injection

### "DLL not found"
- Run `zig build` from project root
- Verify `zig-out/bin/stellaris_quickjs.dll` exists

### "PushCApplicationPtr failed"
- Ensure DLL exported the symbol correctly
- Check `verify_dll.bat` output

### Test mod not loading
- Verify mod is in correct directory
- Check Stellaris launcher mod list
- Enable "Test Mod" in launcher

## Logging

DLL logs are written to:
- Console output (loader window)
- Stellaris error.log (if debug logging enabled)

Check `%USERPROFILE%\Documents\Paradox Interactive\Stellaris\logs\` for engine logs.

## Architecture Notes

The integration tests verify the following pipeline:

```
Loader (C++) → DLL Injection → PushCApplicationPtr → QuickJS Init → JS Execution
                                                                      ↓
                                                    Effect/Trigger Hooks ← Game Engine
                                                                      ↓
                                                    UI Windows ← .gui Files
```

Each test scenario validates one or more stages of this pipeline.
