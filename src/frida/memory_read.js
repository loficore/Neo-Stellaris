/**
 * memory_read.js — Safe memory reading utilities for Stellaris (Clausewitz engine).
 *
 * Designed for Frida instrumentation of stellaris.exe. All reads are wrapped in
 * try-catch to handle invalid pointers, unmapped memory, and other access
 * violations without crashing the target process.
 *
 * Usage (Python side):
 *   session = frida.attach("stellaris.exe")
 *   script = session.create_script(open("memory_read.js").read())
 *   script.load()
 *   exports = script.exports_sync
 *   exports.read_pointer("0x143287360")
 *   exports.read_sso_string("0x...")  # reads Clausewitz SSO string
 */

'use strict';

// ---------------------------------------------------------------------------
// 1. readMemory(address, size)
//    Read `size` raw bytes starting at `address`. Returns byte array or error.
// ---------------------------------------------------------------------------
function readMemory(address, size) {
    try {
        var p = ptr(address);
        var buf = p.readByteArray(size);
        if (buf === null) {
            return { success: false, error: 'readByteArray returned null at ' + p.toString() };
        }
        return { success: true, data: Array.from(new Uint8Array(buf)) };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// ---------------------------------------------------------------------------
// 2. readPointer(address)
//    Read an 8-byte pointer from `address` (x64). Returns hex string.
// ---------------------------------------------------------------------------
function readPointer(address) {
    try {
        var p = ptr(address);
        var val = p.readPointer();  // readPointer handles 64-bit on x64
        return { success: true, value: val.toString(16) };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// ---------------------------------------------------------------------------
// 3. readU32(address)
//    Read a 4-byte unsigned integer.
// ---------------------------------------------------------------------------
function readU32(address) {
    try {
        var p = ptr(address);
        return { success: true, value: p.readU32() };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// ---------------------------------------------------------------------------
// 4. readI32(address)
//    Read a 4-byte signed integer.
// ---------------------------------------------------------------------------
function readI32(address) {
    try {
        var p = ptr(address);
        return { success: true, value: p.readS32() };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// ---------------------------------------------------------------------------
// 5. readU64(address)
//    Read an 8-byte unsigned integer.
// ---------------------------------------------------------------------------
function readU64(address) {
    try {
        var p = ptr(address);
        return { success: true, value: p.readU64().toString(10) };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// ---------------------------------------------------------------------------
// 6. readUtf8String(address, length)
//    Read a UTF-8 string of known length.
// ---------------------------------------------------------------------------
function readUtf8String(address, length) {
    try {
        var p = ptr(address);
        var str = p.readUtf8String(length);
        return { success: true, value: str };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// ---------------------------------------------------------------------------
// 7. followPointerChain(base, offsets)
//    Dereference a pointer at `base`, add offsets[0], dereference again, etc.
//    Returns the final address and its dereferenced value.
// ---------------------------------------------------------------------------
function followPointerChain(base, offsets) {
    try {
        var current = ptr(base);
        var chain = [current.toString(16)];

        for (var i = 0; i < offsets.length; i++) {
            // Dereference current pointer
            var deref = current.readPointer();
            // Add offset
            current = deref.add(offsets[i]);
            chain.push(current.toString(16));
        }

        // Dereference final address to get the value
        var finalValue;
        try {
            finalValue = current.readPointer().toString(16);
        } catch (e) {
            finalValue = null;  // Final address might be a value, not a pointer
        }

        return {
            success: true,
            finalAddress: current.toString(16),
            finalValue: finalValue,
            chain: chain
        };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// ---------------------------------------------------------------------------
// 8. readSSOString(address)
//    Read a Clausewitz/Jomini Small String Optimization string.
//
//    Layout (24 bytes total):
//      offset  0: union { char inline[24]; char* heap_ptr; }
//      offset 22: u8 length
//
//    When length <= 22: string data is stored inline starting at offset 0.
//    When length > 22:  first 8 bytes are a pointer to heap-allocated string.
//
//    Note: The SSO threshold is 22 bytes for Clausewitz engine strings.
// ---------------------------------------------------------------------------
function readSSOString(address) {
    try {
        var p = ptr(address);

        // Read length byte at offset 23
        var length = p.add(22).readU8();

        if (length <= 22) {
            // Inline string: data starts at offset 0, null-terminated within 23 bytes
            var inlineStr = p.readUtf8String(length);
            return {
                success: true,
                value: inlineStr,
                length: length,
                heapAllocated: false
            };
        } else {
            // Heap string: first 8 bytes = pointer to char array
            var strPtr = p.readPointer();
            var heapStr = strPtr.readUtf8String(length);
            return {
                success: true,
                value: heapStr,
                length: length,
                heapAllocated: true
            };
        }
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// ---------------------------------------------------------------------------
// 9. readVtable(address)
//    Read the vtable pointer from an object (offset 0 of a C++ object).
//    Useful for identifying class types via RTTI.
// ---------------------------------------------------------------------------
function readVtable(address) {
    try {
        var p = ptr(address);
        var vtablePtr = p.readPointer();
        return { success: true, vtable: vtablePtr.toString(16) };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// ---------------------------------------------------------------------------
// 10. peekMemory(address, size)
//     Alias for readMemory but intended for quick diagnostic checks.
// ---------------------------------------------------------------------------
function peekMemory(address, size) {
    return readMemory(address, size);
}

// ---------------------------------------------------------------------------
// RPC exports — callable from Python via script.exports_sync.<method>()
// ---------------------------------------------------------------------------
rpc.exports = {
    // Raw byte reading
    readMemory: readMemory,
    readMemoryHex: function (address, size) {
        var result = readMemory(address, size);
        if (!result.success) return result;
        // Convert bytes to hex string for easy inspection
        result.hex = result.data.map(function (b) {
            return ('0' + b.toString(16)).slice(-2);
        }).join(' ');
        return result;
    },

    // Pointer / integer reads
    readPointer: readPointer,
    readU32: readU32,
    readI32: readI32,
    readU64: readU64,

    // String reads
    readUtf8String: readUtf8String,
    readSsoString: readSSOString,

    // Pointer chain traversal
    followPointerChain: followPointerChain,

    // C++ vtable
    readVtable: readVtable,

    // Quick diagnostic peek
    peekMemory: peekMemory,

    // Convenience: read a batch of pointers from an array of addresses
    readPointerBatch: function (addresses) {
        var results = [];
        for (var i = 0; i < addresses.length; i++) {
            results.push(readPointer(addresses[i]));
        }
        return results;
    },

    // Convenience: read a struct-like region and return as key-value pairs
    readStruct: function (address, fields) {
        // fields: [{ name: "vtable", offset: 0, size: 8 }, ...]
        try {
            var p = ptr(address);
            var result = {};
            for (var i = 0; i < fields.length; i++) {
                var f = fields[i];
                var fieldPtr = p.add(f.offset);
                if (f.size === 8) {
                    result[f.name] = fieldPtr.readPointer().toString(16);
                } else if (f.size === 4) {
                    result[f.name] = fieldPtr.readU32();
                } else if (f.size === 1) {
                    result[f.name] = fieldPtr.readU8();
                } else {
                    // Generic byte read
                    var bytes = fieldPtr.readByteArray(f.size);
                    result[f.name] = Array.from(new Uint8Array(bytes));
                }
            }
            return { success: true, struct: result };
        } catch (e) {
            return { success: false, error: e.message };
        }
    }
};
