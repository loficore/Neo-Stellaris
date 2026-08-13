// test.js — Integration test script for stellaris_quickjs DLL
//
// This script is loaded by the QuickJS runtime after DLL injection.
// It registers effect and trigger handlers for testing.

// =============================================================================
// Initialization
// =============================================================================

console.log("=== QuickJS Integration Test Script Loaded ===");
console.log("Timestamp: " + new Date().toISOString());

// =============================================================================
// Effect Handlers
// =============================================================================

// Test custom effect handler
Stellaris.registerEffect("test_custom_effect", (effectName, effectId, scope) => {
    console.log("[EFFECT] test_custom_effect called!");
    console.log("  Effect Name: " + effectName);
    console.log("  Effect ID: " + effectId);
    console.log("  Scope: " + scope);
    return true;
});

// Test logging effect handler
Stellaris.registerEffect("test_logging_effect", (effectName, effectId, scope) => {
    console.log("[EFFECT] test_logging_effect executed");
    console.log("  Scope type: " + Stellaris.getScopeType(scope));
    return true;
});

// Test counter effect handler
let counter = 0;
Stellaris.registerEffect("test_counter_effect", (effectName, effectId, scope) => {
    counter++;
    console.log("[EFFECT] test_counter_effect: counter = " + counter);
    // Update UI if window exists
    try {
        Stellaris.setElementText("test_quickjs_window", "counter", "Counter: " + counter);
    } catch (e) {
        // Window may not exist yet
    }
    return true;
});

// Test conditional effect handler
Stellaris.registerEffect("test_conditional_effect", (effectName, effectId, scope) => {
    const shouldExecute = Math.random() > 0.5;
    console.log("[EFFECT] test_conditional_effect: " + (shouldExecute ? "EXECUTED" : "SKIPPED"));
    return shouldExecute;
});

// Test scope effect handler
Stellaris.registerEffect("test_scope_effect", (effectName, effectId, scope) => {
    const scopeType = Stellaris.getScopeType(scope);
    console.log("[EFFECT] test_scope_effect: scopeType = " + scopeType);
    // Country scope = 2
    return scopeType === 2;
});

// =============================================================================
// Trigger Handlers
// =============================================================================

// Test custom trigger - always returns true
Stellaris.registerTrigger("test_custom_trigger", (triggerName, triggerId, scope) => {
    console.log("[TRIGGER] test_custom_trigger evaluated -> true");
    return true;
});

// Test scope check trigger
Stellaris.registerTrigger("test_scope_check", (triggerName, triggerId, scope) => {
    const scopeType = Stellaris.getScopeType(scope);
    const isCountry = scopeType === 2;
    console.log("[TRIGGER] test_scope_check: scopeType=" + scopeType + " -> " + isCountry);
    return isCountry;
});

// Test flag check trigger
Stellaris.registerTrigger("test_flag_check", (triggerName, triggerId, scope) => {
    // Check if country has the test flag
    const hasFlag = Stellaris.hasCountryFlag(scope, "test_quickjs_flag");
    console.log("[TRIGGER] test_flag_check: hasFlag=" + hasFlag);
    return hasFlag;
});

// Test resource check trigger
Stellaris.registerTrigger("test_resource_check", (triggerName, triggerId, scope) => {
    const energy = Stellaris.getResource(scope, "energy");
    const hasEnough = energy > 100;
    console.log("[TRIGGER] test_resource_check: energy=" + energy + " -> " + hasEnough);
    return hasEnough;
});

// Test year check trigger
Stellaris.registerTrigger("test_year_check", (triggerName, triggerId, scope) => {
    const year = Stellaris.getGameYear();
    const isPastYear = year >= 2200;
    console.log("[TRIGGER] test_year_check: year=" + year + " -> " + isPastYear);
    return isPastYear;
});

// =============================================================================
// Button Effect Handlers
// =============================================================================

// Test button click handler
Stellaris.registerButtonEffect("test_button_click", (buttonName) => {
    console.log("[BUTTON] test_button_click: " + buttonName);
    // Update status text
    try {
        Stellaris.setElementText("test_quickjs_window", "status", "Status: Button Clicked!");
    } catch (e) {
        console.log("[BUTTON] Could not update status: " + e.message);
    }
    return true;
});

// Close window handler
Stellaris.registerButtonEffect("close_test_window", (buttonName) => {
    console.log("[BUTTON] close_test_window: " + buttonName);
    Stellaris.hideWindow("test_quickjs_window");
    return true;
});

// Toggle status handler
let statusState = false;
Stellaris.registerButtonEffect("test_toggle_status", (buttonName) => {
    statusState = !statusState;
    const statusText = statusState ? "Status: Active" : "Status: Ready";
    console.log("[BUTTON] test_toggle_status: " + statusText);
    try {
        Stellaris.setElementText("test_quickjs_window", "status", statusText);
    } catch (e) {
        console.log("[BUTTON] Could not update status: " + e.message);
    }
    return true;
});

// =============================================================================
// Window Management
// =============================================================================

// Show test window function
function showTestWindow() {
    console.log("[UI] Showing test window");
    Stellaris.showWindow("test_quickjs_window");
}

// Hide test window function
function hideTestWindow() {
    console.log("[UI] Hiding test window");
    Stellaris.hideWindow("test_quickjs_window");
}

// =============================================================================
// Initialization Complete
// =============================================================================

console.log("=== QuickJS Integration Test Script Ready ===");
console.log("Registered effects: test_custom_effect, test_logging_effect, test_counter_effect, test_conditional_effect, test_scope_effect");
console.log("Registered triggers: test_custom_trigger, test_scope_check, test_flag_check, test_resource_check, test_year_check");
console.log("Registered buttons: test_button_click, close_test_window, test_toggle_status");
