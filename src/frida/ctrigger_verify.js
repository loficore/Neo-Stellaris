/**
 * CTrigger::Evaluate Verification Script
 * 
 * Hooks candidate trigger evaluation functions to verify:
 * - CTrigger::Evaluate address at 0x1408A6F20 (placeholder)
 * - Trigger ID reading from CTrigger+4080 (0xFF0)
 * - Scope type from CEventScope+8
 * - Object ID from CEventScope+16
 * 
 * Usage:
 *   frida -p <pid> -l ctrigger_verify.js
 *   frida -n stellaris.exe -l ctrigger_verify.js
 */

'use strict';

// ============================================================================
// Configuration
// ============================================================================

const CONFIG = {
    // Candidate CTrigger::Evaluate address (from AGENTS.md context)
    CTRIGGER_EVALUATE: ptr('0x1408A6F20'),
    
    // CTrigger object layout offsets
    CTRIGGER_NAME:           0x038,   // +56: Trigger name (SSO string)
    CTRIGGER_VTABLE:         0x6A8,   // +1704: Vtable pointer
    CTRIGGER_ID:             0xFF0,   // +4080: Trigger ID (i32)
    
    // CEventScope layout offsets
    CEVENTSCOPE_SCOPE_TYPE:  0x08,    // +8: Scope type (int64_t)
    CEVENTSCOPE_OBJECT_ID:   0x10,    // +16: Object ID (int64_t)
    
    // Logging
    MAX_LOG_ENTRIES: 10000,
    LOG_INTERVAL_MS: 1000,  // Batch log interval
};

// ============================================================================
// State
// ============================================================================

const state = {
    hookActive: false,
    hookCount: 0,
    evaluations: [],
    errors: [],
    startTime: Date.now(),
};

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Read a null-terminated string from memory address
 */
function readCString(address, maxLen = 256) {
    try {
        if (address.isNull()) return '<null>';
        return address.readUtf8String(maxLen);
    } catch (e) {
        return '<read_error>';
    }
}

/**
 * Read SSO string (Small String Optimization)
 * SSO string layout: first 8 bytes = size, then inline data or pointer
 */
function readSSOString(address) {
    try {
        if (address.isNull()) return '<null>';
        
        // Read size byte (first byte for SSO)
        const sizeByte = address.readU8();
        
        // Check if SSO is active (size < threshold, typically 16 or 22)
        if (sizeByte < 16) {
            // SSO: string is inline
            return address.add(1).readUtf8String(sizeByte);
        } else {
            // Heap allocated: read pointer at offset 8
            const ptr = address.add(8).readPointer();
            if (ptr.isNull()) return '<null_ptr>';
            return ptr.readUtf8String(256);
        }
    } catch (e) {
        return '<sso_read_error>';
    }
}

/**
 * Format timestamp for logging
 */
function timestamp() {
    return new Date().toISOString();
}

/**
 * Safe hex formatting
 */
function toHex(value) {
    if (typeof value === 'number') {
        return '0x' + value.toString(16).toUpperCase();
    }
    return value.toString();
}

// ============================================================================
// Hook Handler
// ============================================================================

/**
 * Main hook for CTrigger::Evaluate
 */
function hookTriggerEvaluate() {
    console.log(`[*] Attaching to CTrigger::Evaluate at ${CONFIG.CTRIGGER_EVALUATE}`);
    
    Interceptor.attach(CONFIG.CTRIGGER_EVALUATE, {
        onEnter: function(args) {
            this.timestamp = Date.now();
            this.cttrigger = args[0];
            this.ceventscope = args[1];
            this.result = null;
            
            try {
                // Read CTrigger fields
                this.triggerId = this.cttrigger.add(CONFIG.CTRIGGER_ID).readS32();
                this.triggerVtable = this.cttrigger.add(CONFIG.CTRIGGER_VTABLE).readPointer();
                
                // Read CEventScope fields
                this.scopeType = this.ceventscope.add(CONFIG.CEVENTSCOPE_SCOPE_TYPE).readS64();
                this.objectId = this.ceventscope.add(CONFIG.CEVENTSCOPE_OBJECT_ID).readS64();
                
                // Log evaluation
                const logEntry = {
                    timestamp: timestamp(),
                    triggerId: this.triggerId,
                    triggerAddr: this.cttrigger,
                    scopeType: this.scopeType,
                    objectId: this.objectId,
                    vtable: this.triggerVtable,
                };
                
                state.evaluations.push(logEntry);
                state.hookCount++;
                
                // Console output
                console.log(
                    `[TriggerEval #${state.hookCount}] ` +
                    `ID=${this.triggerId} ` +
                    `Scope=${this.scopeType} ` +
                    `Object=${this.objectId} ` +
                    `Vtable=${toHex(this.triggerVtable)}`
                );
                
                // Trim evaluations if too many
                if (state.evaluations.length > CONFIG.MAX_LOG_ENTRIES) {
                    state.evaluations = state.evaluations.slice(-CONFIG.MAX_LOG_ENTRIES / 2);
                }
                
            } catch (e) {
                const error = {
                    timestamp: timestamp(),
                    error: e.message,
                    stack: e.stack,
                };
                state.errors.push(error);
                console.error(`[TriggerEval Error] ${e.message}`);
            }
        },
        
        onLeave: function(retval) {
            try {
                this.result = retval.toInt32();
                
                // Log result if non-zero (trigger matched)
                if (this.result !== 0) {
                    console.log(
                        `[TriggerResult] ` +
                        `ID=${this.triggerId} ` +
                        `Result=${this.result} ` +
                        `Matched=${this.result !== 0 ? 'YES' : 'NO'}`
                    );
                }
                
                // Update last evaluation with result
                if (state.evaluations.length > 0) {
                    const last = state.evaluations[state.evaluations.length - 1];
                    if (last && last.triggerId === this.triggerId) {
                        last.result = this.result;
                        last.duration = Date.now() - this.timestamp;
                    }
                }
                
            } catch (e) {
                console.error(`[TriggerEval Leave Error] ${e.message}`);
            }
        }
    });
    
    state.hookActive = true;
    console.log('[*] Hook attached successfully');
}

// ============================================================================
// Verification Functions
// ============================================================================

/**
 * Verify the hook is active and functioning
 */
function verifyHook() {
    return {
        hookActive: state.hookActive,
        candidateAddress: CONFIG.CTRIGGER_EVALUATE.toString(),
        hookCount: state.hookCount,
        uptime: Date.now() - state.startTime,
        evaluationsCount: state.evaluations.length,
        errorsCount: state.errors.length,
    };
}

/**
 * Get recent evaluations
 */
function getEvaluations(count = 100) {
    return state.evaluations.slice(-count);
}

/**
 * Get evaluation statistics
 */
function getStats() {
    const evaluations = state.evaluations;
    if (evaluations.length === 0) {
        return {
            total: 0,
            matched: 0,
            uniqueTriggers: 0,
            avgDuration: 0,
        };
    }
    
    const matched = evaluations.filter(e => e.result && e.result !== 0).length;
    const uniqueTriggers = new Set(evaluations.map(e => e.triggerId)).size;
    const totalDuration = evaluations.reduce((sum, e) => sum + (e.duration || 0), 0);
    
    return {
        total: evaluations.length,
        matched: matched,
        uniqueTriggers: uniqueTriggers,
        avgDuration: totalDuration / evaluations.length,
    };
}

/**
 * Get errors
 */
function getErrors(count = 50) {
    return state.errors.slice(-count);
}

/**
 * Reset state
 */
function reset() {
    state.evaluations = [];
    state.errors = [];
    state.hookCount = 0;
    state.startTime = Date.now();
    console.log('[*] State reset');
}

// ============================================================================
// RPC Exports
// ============================================================================

rpc.exports = {
    /**
     * Verify hook is active
     * @returns {Object} Hook status
     */
    verifyTrigger: function() {
        return verifyHook();
    },
    
    /**
     * Get recent evaluations
     * @param {number} count - Number of evaluations to return
     * @returns {Array} Evaluation entries
     */
    getEvaluations: function(count) {
        return getEvaluations(count || 100);
    },
    
    /**
     * Get evaluation statistics
     * @returns {Object} Statistics
     */
    getStats: function() {
        return getStats();
    },
    
    /**
     * Get errors
     * @param {number} count - Number of errors to return
     * @returns {Array} Error entries
     */
    getErrors: function(count) {
        return getErrors(count || 50);
    },
    
    /**
     * Reset state
     */
    reset: function() {
        reset();
    },
    
    /**
     * Get configuration
     * @returns {Object} Current config
     */
    getConfig: function() {
        return {
            candidateAddress: CONFIG.CTRIGGER_EVALUATE.toString(),
            triggerIdOffset: CONFIG.CTRIGGER_ID,
            scopeTypeOffset: CONFIG.CEVENTSCOPE_SCOPE_TYPE,
            objectIdOffset: CONFIG.CEVENTSCOPE_OBJECT_ID,
        };
    },
};

// ============================================================================
// Initialization
// ============================================================================

(function main() {
    console.log('='.repeat(60));
    console.log('CTrigger::Evaluate Verification Script');
    console.log('='.repeat(60));
    console.log(`Candidate address: ${CONFIG.CTRIGGER_EVALUATE}`);
    console.log(`CTrigger ID offset: +${CONFIG.CTRIGGER_ID} (0x${CONFIG.CTRIGGER_ID.toString(16)})`);
    console.log(`CEventScope scope offset: +${CONFIG.CEVENTSCOPE_SCOPE_TYPE}`);
    console.log(`CEventScope object offset: +${CONFIG.CEVENTSCOPE_OBJECT_ID}`);
    console.log('='.repeat(60));
    
    try {
        hookTriggerEvaluate();
        console.log('\n[*] Script loaded and hook active');
        console.log('[*] Use RPC exports to query data:');
        console.log('    - rpc.exports.verifyTrigger()');
        console.log('    - rpc.exports.getEvaluations(count)');
        console.log('    - rpc.exports.getStats()');
        console.log('    - rpc.exports.getErrors(count)');
        console.log('    - rpc.exports.reset()');
    } catch (e) {
        console.error(`[!] Failed to attach hook: ${e.message}`);
        console.error(e.stack);
        state.errors.push({
            timestamp: timestamp(),
            error: `Hook attach failed: ${e.message}`,
            stack: e.stack,
        });
    }
})();
