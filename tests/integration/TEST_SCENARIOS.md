# Test Scenarios — Integration Testing

Detailed procedures for each integration test scenario.

---

## T1: DLL Injection Test

### Objective
Verify the DLL can be injected into the Stellaris process and PushCApplicationPtr is called.

### Prerequisites
- Stellaris running
- `stellaris_quickjs.dll` built
- `stellaris-loader.exe` built

### Procedure

1. **Start Stellaris**
   - Launch game from Steam
   - Wait for main menu to load

2. **Run the loader**
   ```batch
   stellaris-loader.exe
   ```
   Or with explicit path:
   ```batch
   stellaris-loader.exe path\to\stellaris_quickjs.dll
   ```

3. **Observe console output**
   Expected output:
   ```
   ========================================
     Stellaris QuickJS Loader
     DLL injection for Clausewitz engine
   ========================================

   [loader] DLL path: C:\...\stellaris_quickjs.dll
   [loader] Found stellaris.exe (PID: 12345)
   [loader] Found "augustus" string at 0x7FF...
   [loader] Injecting DLL...
   [loader] DLL injected successfully
   [loader] Calling PushCApplicationPtr...
   [loader] SUCCESS — CApplication found at 0x7FF...

   [stellaris_quickjs] DLL_PROCESS_ATTACH
   [stellaris_quickjs] CApplication ptr received @ 0x7FF...
   ```

4. **Verify success criteria**
   - [ ] Loader finds stellaris.exe process
   - [ ] "augustus" string located in memory
   - [ ] DLL injects without errors
   - [ ] PushCApplicationPtr called successfully
   - [ ] CApplication pointer is non-null

### Pass Criteria
- Console shows "SUCCESS" message
- CApplication address is valid (non-zero)
- No error messages in output

### Failure Indicators
- "stellaris.exe not found" → Game not running
- "Access denied" → Not running as admin
- "DLL not found" → Build issue
- "PushCApplicationPtr failed" → Export issue

---

## T2: QuickJS Execution Test

### Objective
Verify JavaScript code executes correctly in the game context via QuickJS.

### Prerequisites
- T1 passed (DLL injected successfully)
- QuickJS runtime initialized

### Procedure

1. **Ensure DLL is injected** (T1 complete)

2. **Check QuickJS initialization**
   Look for log output:
   ```
   [stellaris_quickjs] QuickJS runtime initialized
   [stellaris_quickjs] Ready to execute JavaScript
   ```

3. **Execute test script**
   The DLL should auto-load `scripts/test.js` from the mod directory.
   
   Test script content:
   ```javascript
   // Verify QuickJS is working
   console.log("QuickJS test script loaded!");
   
   // Test basic JS functionality
   const result = 2 + 2;
   console.log("Arithmetic test: 2 + 2 = " + result);
   
   // Test Stellaris API availability
   if (typeof Stellaris !== 'undefined') {
       console.log("Stellaris API available");
   } else {
       console.log("Stellaris API not yet available");
   }
   ```

4. **Verify output**
   Expected in console/log:
   ```
   [stellaris_quickjs] QuickJS test script loaded!
   [stellaris_quickjs] Arithmetic test: 2 + 2 = 4
   [stellaris_quickjs] Stellaris API available
   ```

5. **Test error handling**
   Create a test with intentional error:
   ```javascript
   try {
       undefinedFunction();
   } catch (e) {
       console.log("Error caught correctly: " + e.message);
   }
   ```

### Pass Criteria
- [ ] QuickJS runtime initializes
- [ ] JavaScript code executes without crashes
- [ ] Console.log output appears
- [ ] Arithmetic operations work
- [ ] Error handling works correctly

### Failure Indicators
- No QuickJS init message → Runtime failed to start
- JS execution errors → QuickJS integration broken
- Game crashes → Memory corruption

---

## T3: Effect Hook Test

### Objective
Verify custom effects can be registered via JS and triggered in game.

### Prerequisites
- T1 and T2 passed
- Test mod installed with scripted_effects

### Procedure

1. **Verify test mod is installed**
   Check Stellaris launcher shows "Stellaris QuickJS Test" mod enabled.

2. **Check scripted_effects file**
   File: `test_mod/common/scripted_effects/test_effects.txt`
   ```
   test_custom_effect = {
       # This effect is handled by QuickJS
       # The DLL hooks the effect dispatcher and routes to JS
   }
   
   test_logging_effect = {
       # Test effect that logs when executed
   }
   ```

3. **Verify JS handler registration**
   The test.js file should register handlers:
   ```javascript
   Stellaris.registerEffect("test_custom_effect", (scope) => {
       console.log("test_custom_effect called!");
       return true;
   });
   
   Stellaris.registerEffect("test_logging_effect", (scope) => {
       console.log("test_logging_effect executed in scope: " + scope);
       return true;
   });
   ```

4. **Trigger effect in game**
   - Start a new game (or load save)
   - Open console (F12 or ~)
   - Execute: `test_custom_effect`
   
   Or trigger via event:
   - The test event file triggers the effect
   - Wait for event to fire (on_yearly_pulse)

5. **Verify callback execution**
   Check console/log for:
   ```
   [stellaris_quickjs] Effect 'test_custom_effect' registered
   [stellaris_quickjs] test_custom_effect called!
   [stellaris_quickjs] Effect handler invoked successfully
   ```

### Pass Criteria
- [ ] Effect handler registers without errors
- [ ] Effect can be triggered in game
- [ ] JS callback executes
- [ ] Console output confirms execution
- [ ] No game crashes

### Failure Indicators
- Registration fails → Handler system not initialized
- Effect not triggered → Hook not installed
- JS error → Callback function broken

---

## T4: Trigger Hook Test

### Objective
Verify custom triggers can be registered via JS and evaluated in game scripts.

### Prerequisites
- T1 and T2 passed
- Test mod installed with scripted_triggers

### Procedure

1. **Verify test mod is installed**
   Check `test_mod/common/scripted_triggers/test_triggers.txt`:
   ```
   test_custom_trigger = {
       # Evaluated by QuickJS
       # Returns true/false based on JS handler
   }
   
   test_scope_check = {
       # Checks scope type via JS
   }
   ```

2. **Verify JS handler registration**
   ```javascript
   Stellaris.registerTrigger("test_custom_trigger", (scope) => {
       console.log("test_custom_trigger evaluated");
       return true; // Always passes
   });
   
   Stellaris.registerTrigger("test_scope_check", (scope) => {
       const scopeType = Stellaris.getScopeType(scope);
       console.log("Scope type: " + scopeType);
       return scopeType === 2; // Check for country scope
   });
   ```

3. **Use trigger in game script**
   Create a test event that uses the trigger:
   File: `test_mod/events/test_trigger_event.txt`
   ```
   country_event = {
       id = test_trigger.1
       title = "Test Trigger Event"
       desc = "This event tests custom triggers"
       
       trigger = {
           test_custom_trigger = yes
       }
       
       immediate = {
           log = "Trigger test event fired!"
       }
   }
   ```

4. **Trigger the event**
   - Start new game
   - Use console: `event test_trigger.1`
   - Or wait for natural trigger

5. **Verify trigger evaluation**
   Check log for:
   ```
   [stellaris_quickjs] Trigger 'test_custom_trigger' registered
   [stellaris_quickjs] test_custom_trigger evaluated
   [stellaris_quickjs] Trigger returned: true
   ```

### Pass Criteria
- [ ] Trigger handler registers without errors
- [ ] Trigger evaluates when used in script
- [ ] JS handler returns correct boolean
- [ ] Game logic respects trigger result
- [ ] No crashes during evaluation

### Failure Indicators
- Registration fails → Runtime not ready
- Trigger not evaluated → Hook not installed
- Wrong return value → JS logic error

---

## T5: UI Integration Test

### Objective
Verify custom UI windows can be created and displayed via .gui files.

### Prerequisites
- T1 passed
- Test mod installed with interface files

### Procedure

1. **Verify .gui file exists**
   File: `test_mod/interface/test_window.gui`
   ```
   containerWindowType = {
       name = "test_quickjs_window"
       size = { width = 400 height = 300 }
       draggable = yes
       movable = yes
       
       instantTextBoxType = {
           name = "title"
           text = "QuickJS Test Window"
           font = "cg_20"
           position = { x = 10 y = 10 }
       }
       
       instantTextBoxType = {
           name = "status"
           text = "Status: Ready"
           font = "cg_16"
           position = { x = 10 y = 40 }
       }
       
       effectButtonType = {
           name = "test_button"
           effect = "test_button_click"
           position = { x = 10 y = 250 }
           size = { width = 120 height = 30 }
           tooltip = "Click to test"
       }
       
       effectButtonType = {
           name = "close_button"
           effect = "close_test_window"
           position = { x = 350 y = 250 }
           size = { width = 40 height = 25 }
           tooltip = "Close"
       }
   }
   ```

2. **Verify button_effects file**
   File: `test_mod/common/button_effects/test_buttons.txt`
   ```
   test_button_click = {
       tooltip = "Test Button"
   }
   
   close_test_window = {
       tooltip = "Close Window"
   }
   ```

3. **Register button callbacks in JS**
   ```javascript
   Stellaris.registerButtonEffect("test_button_click", (btnName) => {
       console.log("Button clicked: " + btnName);
       Stellaris.setWindowTitle("test_quickjs_window", "Button Clicked!");
       return true;
   });
   
   Stellaris.registerButtonEffect("close_test_window", (btnName) => {
       console.log("Closing window");
       Stellaris.hideWindow("test_quickjs_window");
       return true;
   });
   ```

4. **Show window in game**
   - Start new game
   - Open console
   - Execute: `test_show_window`
   
   Or use JS:
   ```javascript
   Stellaris.showWindow("test_quickjs_window");
   ```

5. **Verify window display**
   - [ ] Window appears on screen
   - [ ] Title text displays correctly
   - [ ] Status text shows "Status: Ready"
   - [ ] Buttons are clickable
   - [ ] Window can be dragged
   - [ ] Close button works

6. **Test button interaction**
   - Click "Test Button"
   - Verify console output: "Button clicked: test_button_click"
   - Verify window title changes to "Button Clicked!"
   - Click "Close" button
   - Verify window hides

### Pass Criteria
- [ ] .gui file loads without errors
- [ ] Window appears in game
- [ ] All UI elements render correctly
- [ ] Button clicks trigger JS callbacks
- [ ] Window state changes work (show/hide)
- [ ] No rendering glitches

### Failure Indicators
- Window not found → .gui file not loaded
- Elements missing → Syntax error in .gui
- Buttons unresponsive → Effect not registered
- Crashes → Memory issues in UI system

---

## Additional Tests

### T6: Multi-thread Stress Test

Test effect/trigger handlers under concurrent execution:

1. Register multiple effects/triggers
2. Trigger them rapidly via console
3. Verify no race conditions or crashes

### T7: Hot Reload Test

Test script reloading:

1. Inject DLL
2. Modify test.js
3. Trigger reload (if supported)
4. Verify new code executes

### T8: Memory Leak Test

Test for memory leaks:

1. Inject DLL
2. Run effects/triggers repeatedly
3. Monitor memory usage
4. Verify no unbounded growth

---

## Evidence Collection

Test results should be saved to `evidence/` directory:

- `evidence/T1_injection_result.txt` — Console output from injection
- `evidence/T2_quickjs_output.txt` — QuickJS execution logs
- `evidence/T3_effect_hooks.log` — Effect registration and execution
- `evidence/T4_trigger_hooks.log` — Trigger evaluation logs
- `evidence/T5_ui_screenshots/` — Screenshots of UI windows
- `evidence/errors/` — Any errors encountered

Use `run_tests.ps1 -CollectEvidence` to automatically capture results.
