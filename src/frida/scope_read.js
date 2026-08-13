/**
 * CEventScope Reader - Frida Script
 *
 * Reads CEventScope information at runtime:
 *   +8:  Scope type (int64_t) - bit flag enum
 *   +16: Object ID  (int64_t) - game object identifier
 *
 * Usage (CLI):
 *   frida -p <pid> -l scope_read.js
 *
 * Usage (RPC from Python/other):
 *   script = session.create_script(open('scope_read.js').read())
 *   script.load()
 *   result = script.exports.read_scope("0x...")
 */

'use strict';

// ── Scope type enum (bit-flag values) ──────────────────────────────────────
var SCOPE_TYPES = {
    2:       "PLANET",
    4:       "COUNTRY",
    8:       "SHIP",
    16:      "POP",
    32:      "FLEET",
    64:      "GALACTIC_OBJECT",
    128:     "LEADER",
    256:     "ARMY",
    512:     "AMBIENT_OBJECT",
    1024:    "SPECIES",
    1048576: "NO_SCOPE"
};

// Reverse lookup: name -> value
var SCOPE_NAMES = {};
Object.keys(SCOPE_TYPES).forEach(function (key) {
    SCOPE_NAMES[SCOPE_TYPES[key]] = parseInt(key, 10);
});

// ── Core read function ─────────────────────────────────────────────────────
function readScopeAt(address) {
    var p = ptr(address);

    var scopeType = p.add(8).readS64();
    var objectId  = p.add(16).readS64();

    var scopeName = SCOPE_TYPES[scopeType];
    if (scopeName === undefined) {
        scopeName = "UNKNOWN_0x" + scopeType.toString(16);
    }

    return {
        scopeType: scopeType,
        scopeName: scopeName,
        objectId:  objectId.toString()
    };
}

// ── Pretty-print a single scope ────────────────────────────────────────────
function formatScope(result) {
    return "[CEventScope] type=" + result.scopeName
        + " (0x" + result.scopeType.toString(16) + ")"
        + "  objectId=" + result.objectId;
}

// ── Read a chain of scopes (prev/parent linked) ────────────────────────────
// CEventScope layout assumed:
//   +0:  vtable
//   +8:  scope type (int64)
//   +16: object id  (int64)
//   +24: prev scope pointer (CEventScope*)
function readScopeChain(scopeAddress, maxDepth) {
    maxDepth = maxDepth || 10;
    var chain = [];
    var current = ptr(scopeAddress);

    for (var i = 0; i < maxDepth; i++) {
        if (current.isNull()) break;

        try {
            var info = readScopeAt(current);
            info.depth = i;
            chain.push(info);
            // Follow "prev" pointer at +24 if it looks sane
            var nextPtr = current.add(24).readPointer();
            if (nextPtr.isNull() || nextPtr.equals(current)) break;
            current = nextPtr;
        } catch (e) {
            break;
        }
    }
    return chain;
}

// ── RPC exports ────────────────────────────────────────────────────────────
rpc.exports = {
    /**
     * Read a single CEventScope at the given address.
     * @param {string|number} scopeAddress  - hex address (e.g. "0x7FFA12345678") or integer
     * @returns {{ scopeType: number, scopeName: string, objectId: string }}
     */
    readScope: function (scopeAddress) {
        return readScopeAt(scopeAddress);
    },

    /**
     * Read a CEventScope and return a human-readable string.
     * @param {string|number} scopeAddress
     * @returns {string}
     */
    readScopeFormatted: function (scopeAddress) {
        return formatScope(readScopeAt(scopeAddress));
    },

    /**
     * Walk a scope chain via the prev pointer at +24.
     * @param {string|number} scopeAddress
     * @param {number}         [maxDepth=10]
     * @returns {Array<{scopeType, scopeName, objectId, depth}>}
     */
    readScopeChain: function (scopeAddress, maxDepth) {
        return readScopeChain(scopeAddress, maxDepth || 10);
    },

    /**
     * Resolve a scope type name to its numeric value.
     * @param {string} name  - e.g. "PLANET", "COUNTRY"
     * @returns {number|null}
     */
    resolveScopeType: function (name) {
        var upper = (name || "").toUpperCase();
        return SCOPE_NAMES[upper] !== undefined ? SCOPE_NAMES[upper] : null;
    },

    /**
     * Return the full scope type map for enumeration.
     * @returns {{ [value: number]: string }}
     */
    listScopeTypes: function () {
        return SCOPE_TYPES;
    }
};

// ── Console banner ─────────────────────────────────────────────────────────
console.log("[scope_read.js] CEventScope reader loaded");
console.log("[scope_read.js] RPC exports: readScope, readScopeFormatted, readScopeChain, resolveScopeType, listScopeTypes");
