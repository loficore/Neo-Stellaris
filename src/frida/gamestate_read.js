/**
 * gamestate_read.js — Frida script to read GameState fields at runtime.
 *
 * Reads GameState pointer from global address 0x143287360, CountryDB from
 * 0x143287788, game date, tick count, and provides country lookup by ID.
 *
 * Usage (Python side):
 *   import frida
 *   session = frida.attach("stellaris.exe")
 *   script = session.create_script(open("gamestate_read.js").read())
 *   script.load()
 *   exports = script.exports_sync
 *   state = exports.getGameState()
 *   country = exports.getCountry(1)
 */

'use strict';

// ---------------------------------------------------------------------------
// Global addresses (from IDA reverse engineering)
// ---------------------------------------------------------------------------
var ADDRESSES = {
    GameState: ptr('0x143287360'),
    CountryDB: ptr('0x143287788'),
    EventDB: ptr('0x14339AFE8')
};

// ---------------------------------------------------------------------------
// GameState field offsets (estimated from IDA analysis)
// ---------------------------------------------------------------------------
var GAMESTATE_OFFSETS = {
    GameDate: 0x00,      // +0x00: Game date (string or pointer to string)
    GameTick: 0x08,      // +0x08: Game tick (i64)
    CountryDB: 0x10,     // +0x10: CountryDB pointer
    PlanetDB: 0x18,      // +0x18: PlanetDB pointer
    SystemDB: 0x20,      // +0x20: StarSystemDB pointer
    PopDB: 0x28          // +0x28: PopDB pointer
};

// ---------------------------------------------------------------------------
// Helper: Safe memory read with error handling
// ---------------------------------------------------------------------------
function safeRead(address, reader, fallback) {
    try {
        var p = ptr(address);
        return reader(p);
    } catch (e) {
        return fallback !== undefined ? fallback : null;
    }
}

// ---------------------------------------------------------------------------
// 1. getGameStatePointer()
//    Read the main GameState pointer from the global address.
// ---------------------------------------------------------------------------
function getGameStatePointer() {
    try {
        var gameStatePtr = ADDRESSES.GameState.readPointer();
        return {
            success: true,
            address: ADDRESSES.GameState.toString(16),
            value: gameStatePtr.toString(16)
        };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// ---------------------------------------------------------------------------
// 2. readGameDate()
//    Read the current in-game date string from GameState.
//    Offset +0x00 contains either an inline SSO string or a pointer to the date.
// ---------------------------------------------------------------------------
function readGameDate() {
    try {
        var gameStatePtr = ADDRESSES.GameState.readPointer();
        var dateOffset = gameStatePtr.add(GAMESTATE_OFFSETS.GameDate);

        // Read length byte at offset 23 (SSO format)
        var length = dateOffset.add(22).readU8();

        if (length === 0) {
            return { success: true, value: '', length: 0 };
        }

        var dateStr;
        if (length <= 22) {
            // Inline SSO string
            dateStr = dateOffset.readUtf8String(length);
        } else {
            // Heap-allocated string: first 8 bytes = pointer
            var strPtr = dateOffset.readPointer();
            dateStr = strPtr.readUtf8String(length);
        }

        return {
            success: true,
            value: dateStr,
            length: length
        };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// ---------------------------------------------------------------------------
// 3. readGameTick()
//    Read the current game tick count (i64) from GameState.
//    Offset +0x08 contains the tick counter.
// ---------------------------------------------------------------------------
function readGameTick() {
    try {
        var gameStatePtr = ADDRESSES.GameState.readPointer();
        var tickValue = gameStatePtr.add(GAMESTATE_OFFSETS.GameTick).readU64();

        return {
            success: true,
            value: tickValue.toString(10)
        };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// ---------------------------------------------------------------------------
// 4. getCountryDBPointer()
//    Read the CountryDB pointer from GameState or from the global address.
// ---------------------------------------------------------------------------
function getCountryDBPointer() {
    try {
        // First try reading from GameState
        var gameStatePtr = ADDRESSES.GameState.readPointer();
        var countryDBPtr = gameStatePtr.add(GAMESTATE_OFFSETS.CountryDB).readPointer();

        if (countryDBPtr.isNull()) {
            // Fallback to global address
            countryDBPtr = ADDRESSES.CountryDB.readPointer();
        }

        return {
            success: true,
            address: countryDBPtr.toString(16)
        };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// ---------------------------------------------------------------------------
// 5. getCountryCount()
//    Get the number of countries in the CountryDB.
//    CountryDB is typically a BST or vector; read the count field.
// ---------------------------------------------------------------------------
function getCountryCount() {
    try {
        var countryDBPtr = ADDRESSES.CountryDB.readPointer();

        // Common offset for count in database containers
        // Adjust this based on actual reverse engineering
        var countOffset = 0x08;  // Typical count offset
        var count = countryDBPtr.add(countOffset).readU32();

        return {
            success: true,
            count: count
        };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// ---------------------------------------------------------------------------
// 6. getCountryById(id)
//    Look up a country by its numeric ID in the CountryDB.
//    Returns pointer to country object or null.
// ---------------------------------------------------------------------------
function getCountryById(id) {
    try {
        var countryDBPtr = ADDRESSES.CountryDB.readPointer();

        // Clausewitz uses BST (Binary Search Tree) for databases
        // Read the root node at offset 0x00
        var rootNode = countryDBPtr.readPointer();

        if (rootNode.isNull()) {
            return { success: true, found: false, country: null };
        }

        // Traverse BST to find country with matching ID
        var current = rootNode;
        var maxDepth = 100;  // Safety limit

        while (!current.isNull() && maxDepth-- > 0) {
            // Read country ID from node (offset 0x10 is typical for key)
            var nodeId = current.add(0x10).readS32();

            if (nodeId === id) {
                // Found! Read country object pointer
                var countryObj = current.add(0x18).readPointer();
                return {
                    success: true,
                    found: true,
                    countryId: nodeId,
                    address: countryObj.toString(16)
                };
            } else if (nodeId < id) {
                // Go right (offset 0x08 for right child)
                current = current.add(0x08).readPointer();
            } else {
                // Go left (offset 0x00 for left child)
                current = current.readPointer();
            }
        }

        return { success: true, found: false, country: null };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// ---------------------------------------------------------------------------
// 7. readCountryField(countryAddress, fieldOffset, size)
//    Read a field from a country object at the given offset.
// ---------------------------------------------------------------------------
function readCountryField(countryAddress, fieldOffset, size) {
    try {
        var p = ptr(countryAddress).add(fieldOffset);
        var value;

        if (size === 8) {
            value = p.readPointer().toString(16);
        } else if (size === 4) {
            value = p.readU32();
        } else if (size === 2) {
            value = p.readU16();
        } else if (size === 1) {
            value = p.readU8();
        } else {
            // Generic byte read
            var bytes = p.readByteArray(size);
            value = Array.from(new Uint8Array(bytes));
        }

        return {
            success: true,
            address: p.toString(16),
            value: value
        };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// ---------------------------------------------------------------------------
// 8. readCountryName(countryAddress)
//    Read the country name string (SSO format) from a country object.
//    Common offsets: 0x20 or 0x28 for name field.
// ---------------------------------------------------------------------------
function readCountryName(countryAddress) {
    try {
        var p = ptr(countryAddress);
        var nameOffset = 0x28;  // Typical name offset in country object

        var namePtr = p.add(nameOffset);
        var length = namePtr.add(22).readU8();

        if (length === 0) {
            return { success: true, value: '', length: 0 };
        }

        var nameStr;
        if (length <= 22) {
            nameStr = namePtr.readUtf8String(length);
        } else {
            var strPtr = namePtr.readPointer();
            nameStr = strPtr.readUtf8String(length);
        }

        return {
            success: true,
            value: nameStr,
            length: length
        };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// ---------------------------------------------------------------------------
// 9. getDatabaseInfo()
//    Get summary info about all databases (GameState, CountryDB, etc.)
// ---------------------------------------------------------------------------
function getDatabaseInfo() {
    try {
        var info = {
            gameState: getGameStatePointer(),
            countryDB: getCountryDBPointer(),
            countryCount: getCountryCount(),
            gameDate: readGameDate(),
            gameTick: readGameTick()
        };
        return { success: true, info: info };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// ---------------------------------------------------------------------------
// 10. getGameState()
//     Get complete GameState as a structured object.
// ---------------------------------------------------------------------------
function getGameState() {
    try {
        return {
            date: readGameDate(),
            tick: readGameTick(),
            countryCount: getCountryCount()
        };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// ---------------------------------------------------------------------------
// 11. getCountry(id)
//     Get country data by ID, including name and basic fields.
// ---------------------------------------------------------------------------
function getCountry(id) {
    try {
        var country = getCountryById(id);
        if (!country.success || !country.found) {
            return { success: true, found: false, country: null };
        }

        var name = readCountryName(country.address);

        return {
            success: true,
            found: true,
            country: {
                id: id,
                address: country.address,
                name: name.value
            }
        };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// ---------------------------------------------------------------------------
// RPC exports — callable from Python via script.exports_sync.<method>()
// ---------------------------------------------------------------------------
rpc.exports = {
    // GameState access
    getGameStatePointer: getGameStatePointer,
    getGameState: getGameState,
    getDatabaseInfo: getDatabaseInfo,

    // Date and tick
    readGameDate: readGameDate,
    readGameTick: readGameTick,

    // Country database
    getCountryDBPointer: getCountryDBPointer,
    getCountryCount: getCountryCount,
    getCountryById: getCountryById,
    getCountry: getCountry,
    readCountryField: readCountryField,
    readCountryName: readCountryName,

    // Convenience: read multiple fields from country
    getCountryFields: function (id, fields) {
        try {
            var country = getCountryById(id);
            if (!country.success || !country.found) {
                return { success: true, found: false, fields: null };
            }

            var result = {};
            for (var i = 0; i < fields.length; i++) {
                var f = fields[i];
                var fieldResult = readCountryField(country.address, f.offset, f.size);
                if (fieldResult.success) {
                    result[f.name] = fieldResult.value;
                }
            }

            return { success: true, found: true, fields: result };
        } catch (e) {
            return { success: false, error: e.message };
        }
    },

    // Batch read countries by IDs
    getCountries: function (ids) {
        try {
            var results = [];
            for (var i = 0; i < ids.length; i++) {
                results.push(getCountry(ids[i]));
            }
            return { success: true, countries: results };
        } catch (e) {
            return { success: false, error: e.message };
        }
    }
};
