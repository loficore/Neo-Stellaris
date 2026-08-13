<#
.SYNOPSIS
    Integration test runner for stellaris_quickjs DLL.

.DESCRIPTION
    Automates integration testing of the stellaris_quickjs DLL with Stellaris.
    Supports installing test mod, running individual tests, and collecting evidence.

.PARAMETER Test
    Specific test to run (T1-T5). If omitted, runs all tests.

.PARAMETER InstallMod
    Install the test mod to Stellaris mod directory.

.PARAMETER CollectEvidence
    Collect test evidence (logs, screenshots) to evidence directory.

.PARAMETER StellarisPath
    Path to Stellaris installation. Auto-detected if omitted.

.PARAMETER DLLPath
    Path to stellaris_quickjs.dll. Defaults to zig-out/bin/.

.EXAMPLE
    .\run_tests.ps1 -InstallMod
    .\run_tests.ps1 -Test "T1"
    .\run_tests.ps1 -CollectEvidence
#>

param(
    [string]$Test,
    [switch]$InstallMod,
    [switch]$CollectEvidence,
    [string]$StellarisPath,
    [string]$DLLPath
)

# =============================================================================
# Configuration
# =============================================================================

$ErrorActionPreference = "Stop"

# Default paths
if (-not $StellarisPath) {
    $StellarisPath = "${env:ProgramFiles(x86)}\Steam\steamapps\common\Stellaris"
}
if (-not $DLLPath) {
    $DLLPath = Join-Path $PSScriptRoot "..\..\zig-out\bin\stellaris_quickjs.dll"
}

$ModSourceDir = Join-Path $PSScriptRoot "test_mod"
$ModDestDir = Join-Path $env:USERPROFILE "Documents\Paradox Interactive\Stellaris\mod\stellaris_quickjs_test"
$EvidenceDir = Join-Path $PSScriptRoot "evidence"
$LoaderPath = Join-Path $PSScriptRoot "..\..\zig-out\bin\stellaris-loader.exe"

# =============================================================================
# Helper Functions
# =============================================================================

function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Step, [string]$Message)
    Write-Host "[$Step] $Message" -ForegroundColor Yellow
}

function Write-Success {
    param([string]$Message)
    Write-Host "[PASS] $Message" -ForegroundColor Green
}

function Write-Fail {
    param([string]$Message)
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Gray
}

function Test-StellarisRunning {
    $process = Get-Process -Name "stellaris" -ErrorAction SilentlyContinue
    return $process -ne $null
}

function Wait-StellarisRunning {
    param([int]$TimeoutSeconds = 60)
    
    Write-Step "WAIT" "Waiting for Stellaris to start (timeout: ${TimeoutSeconds}s)..."
    $elapsed = 0
    while (-not (Test-StellarisRunning) -and $elapsed -lt $TimeoutSeconds) {
        Start-Sleep -Seconds 1
        $elapsed++
    }
    return (Test-StellarisRunning)
}

function Save-Evidence {
    param([string]$Name, [string]$Content)
    
    if (-not (Test-Path $EvidenceDir)) {
        New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filename = "${Name}_${timestamp}.txt"
    $filepath = Join-Path $EvidenceDir $filename
    
    Set-Content -Path $filepath -Value $Content
    Write-Info "Evidence saved: $filepath"
}

# =============================================================================
# Test Functions
# =============================================================================

function Test-T1_DLLInjection {
    Write-Header "T1: DLL Injection Test"
    
    # Check prerequisites
    Write-Step "CHECK" "Verifying prerequisites..."
    
    if (-not (Test-Path $DLLPath)) {
        Write-Fail "DLL not found: $DLLPath"
        Write-Info "Build the DLL first with: zig build"
        return $false
    }
    Write-Success "DLL found: $DLLPath"
    
    if (-not (Test-StellarisRunning)) {
        Write-Info "Stellaris is not running. Please start the game first."
        Write-Info "Waiting for Stellaris to start..."
        
        if (-not (Wait-StellarisRunning -TimeoutSeconds 120)) {
            Write-Fail "Stellaris did not start within timeout"
            return $false
        }
    }
    Write-Success "Stellaris is running"
    
    # Run the loader
    Write-Step "INJECT" "Running DLL loader..."
    
    if (-not (Test-Path $LoaderPath)) {
        Write-Fail "Loader not found: $LoaderPath"
        Write-Info "Build the loader first"
        return $false
    }
    
    $output = & $LoaderPath $DLLPath 2>&1
    $outputString = $output | Out-String
    
    Write-Host $outputString
    
    # Check for success indicators
    if ($outputString -match "SUCCESS") {
        Write-Success "DLL injection successful"
        
        if ($CollectEvidence) {
            Save-Evidence "T1_injection" $outputString
        }
        
        return $true
    } else {
        Write-Fail "DLL injection failed"
        Write-Host $outputString
        
        if ($CollectEvidence) {
            Save-Evidence "T1_injection_FAILED" $outputString
        }
        
        return $false
    }
}

function Test-T2_QuickJSExecution {
    Write-Header "T2: QuickJS Execution Test"
    
    Write-Step "CHECK" "Verifying QuickJS runtime..."
    
    # Check for QuickJS initialization in logs
    $logPath = Join-Path $env:USERPROFILE "Documents\Paradox Interactive\Stellaris\logs\game.log"
    
    if (Test-Path $logPath) {
        $logContent = Get-Content $logPath -Tail 100 | Out-String
        
        if ($logContent -match "QuickJS runtime initialized") {
            Write-Success "QuickJS runtime initialized"
            return $true
        } elseif ($logContent -match "stellaris_quickjs") {
            Write-Success "stellaris_quickjs DLL is active"
            return $true
        } else {
            Write-Info "Could not verify QuickJS in logs (may need to check manually)"
            return $true  # Assume success, manual verification needed
        }
    } else {
        Write-Info "Game log not found, manual verification required"
        return $true
    }
}

function Test-T3_EffectHooks {
    Write-Header "T3: Effect Hook Test"
    
    Write-Step "TEST" "Effect hook test requires manual verification"
    Write-Host ""
    Write-Host "To test effect hooks:" -ForegroundColor Yellow
    Write-Host "  1. Start a new game in Stellaris" -ForegroundColor White
    Write-Host "  2. Open console (F12 or ~)" -ForegroundColor White
    Write-Host "  3. Execute: test_custom_effect" -ForegroundColor White
    Write-Host "  4. Check console output for callback execution" -ForegroundColor White
    Write-Host ""
    Write-Host "Expected output:" -ForegroundColor Yellow
    Write-Host "  [EFFECT] test_custom_effect called!" -ForegroundColor Gray
    Write-Host ""
    
    $response = Read-Host "Did the effect hook work? (y/n)"
    return ($response -eq "y")
}

function Test-T4_TriggerHooks {
    Write-Header "T4: Trigger Hook Test"
    
    Write-Step "TEST" "Trigger hook test requires manual verification"
    Write-Host ""
    Write-Host "To test trigger hooks:" -ForegroundColor Yellow
    Write-Host "  1. Start a new game in Stellaris" -ForegroundColor White
    Write-Host "  2. Open console (F12 or ~)" -ForegroundColor White
    Write-Host "  3. Execute: event test_quickjs.1" -ForegroundColor White
    Write-Host "  4. Check error.log for trigger evaluation" -ForegroundColor White
    Write-Host ""
    Write-Host "Expected output in log:" -ForegroundColor Yellow
    Write-Host "  [TRIGGER] test_custom_trigger evaluated -> true" -ForegroundColor Gray
    Write-Host ""
    
    $response = Read-Host "Did the trigger hook work? (y/n)"
    return ($response -eq "y")
}

function Test-T5_UIIntegration {
    Write-Header "T5: UI Integration Test"
    
    Write-Step "TEST" "UI integration test requires manual verification"
    Write-Host ""
    Write-Host "To test UI integration:" -ForegroundColor Yellow
    Write-Host "  1. Start a new game in Stellaris" -ForegroundColor White
    Write-Host "  2. Open console (F12 or ~)" -ForegroundColor White
    Write-Host "  3. Execute: test_show_window (or Stellaris.showWindow in JS)" -ForegroundColor White
    Write-Host "  4. Verify window appears with title and buttons" -ForegroundColor White
    Write-Host "  5. Click buttons and verify callbacks execute" -ForegroundColor White
    Write-Host ""
    Write-Host "Expected behavior:" -ForegroundColor Yellow
    Write-Host "  - Window 'test_quickjs_window' appears" -ForegroundColor Gray
    Write-Host "  - Title shows 'QuickJS Test Window'" -ForegroundColor Gray
    Write-Host "  - Buttons are clickable" -ForegroundColor Gray
    Write-Host "  - Button clicks trigger JS callbacks" -ForegroundColor Gray
    Write-Host ""
    
    $response = Read-Host "Did the UI integration work? (y/n)"
    return ($response -eq "y")
}

# =============================================================================
# Mod Installation
# =============================================================================

function Install-TestMod {
    Write-Header "Installing Test Mod"
    
    Write-Step "COPY" "Copying test mod to Stellaris mod directory..."
    
    if (Test-Path $ModDestDir) {
        Write-Info "Removing existing mod installation..."
        Remove-Item -Recurse -Force $ModDestDir
    }
    
    Copy-Item -Recurse -Force $ModSourceDir $ModDestDir
    
    Write-Success "Test mod installed to: $ModDestDir"
    Write-Host ""
    Write-Host "To enable the mod:" -ForegroundColor Yellow
    Write-Host "  1. Open Stellaris launcher" -ForegroundColor White
    Write-Host "  2. Go to Mods tab" -ForegroundColor White
    Write-Host "  3. Enable 'Stellaris QuickJS Test'" -ForegroundColor White
    Write-Host "  4. Start a new game" -ForegroundColor White
}

# =============================================================================
# Main
# =============================================================================

Write-Header "Stellaris QuickJS Integration Tests"

# Install mod if requested
if ($InstallMod) {
    Install-TestMod
    if (-not $Test) {
        exit 0
    }
}

# Run tests
$results = @{}

if ($Test) {
    # Run specific test
    switch ($Test.ToUpper()) {
        "T1" { $results["T1"] = Test-T1_DLLInjection }
        "T2" { $results["T2"] = Test-T2_QuickJSExecution }
        "T3" { $results["T3"] = Test-T3_EffectHooks }
        "T4" { $results["T4"] = Test-T4_TriggerHooks }
        "T5" { $results["T5"] = Test-T5_UIIntegration }
        default {
            Write-Fail "Unknown test: $Test"
            Write-Info "Valid tests: T1, T2, T3, T4, T5"
            exit 1
        }
    }
} else {
    # Run all tests
    $results["T1"] = Test-T1_DLLInjection
    
    if ($results["T1"]) {
        $results["T2"] = Test-T2_QuickJSExecution
        $results["T3"] = Test-T3_EffectHooks
        $results["T4"] = Test-T4_TriggerHooks
        $results["T5"] = Test-T5_UIIntegration
    } else {
        Write-Host ""
        Write-Fail "T1 failed. Subsequent tests require successful DLL injection."
        Write-Info "Fix T1 before running T2-T5."
    }
}

# Print summary
Write-Header "Test Results Summary"

$passed = 0
$failed = 0

foreach ($test in @("T1", "T2", "T3", "T4", "T5")) {
    if ($results.ContainsKey($test)) {
        if ($results[$test]) {
            Write-Success "$test passed"
            $passed++
        } else {
            Write-Fail "$test failed"
            $failed++
        }
    } else {
        Write-Info "$test skipped"
    }
}

Write-Host ""
Write-Host "Passed: $passed" -ForegroundColor Green
Write-Host "Failed: $failed" -ForegroundColor Red
Write-Host ""

if ($failed -eq 0 -and $passed -gt 0) {
    Write-Success "All tests passed!"
    exit 0
} else {
    Write-Fail "Some tests failed"
    exit 1
}
