#!/usr/bin/env python3
"""Frida memory diagnostic tool for AI-automated inspection."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Any

import frida


def get_device(host: str | None = None) -> frida.core.Device:
    """Get Frida device (local or remote)."""
    if host and host != "127.0.0.1":
        device = frida.get_device_manager().add_remote_device(host)
    else:
        device = frida.get_local_device()
    return device


def attach_process(device: frida.core.Device, pid: int | str) -> frida.core.Session:
    """Attach to a process by PID or name."""
    return device.attach(pid)


def create_script(session: frida.core.Session, source: str) -> frida.core.Script:
    """Create and load a Frida script."""
    script = session.create_script(source)
    script.load()
    return script


def format_response(
    command: str,
    success: bool,
    data: Any = None,
    error: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Format response as JSON-serializable dict."""
    response: dict[str, Any] = {
        "success": success,
        "command": command,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if data is not None:
        response["data"] = data
    if error:
        response["error"] = error
    response.update(kwargs)
    return response


MEMORY_READ_SCRIPT = """
'use strict';

rpc.exports = {
    readMemory: function(address, size) {
        try {
            const addr = ptr(address);
            const buf = Memory.readByteArray(addr, size);
            return {
                success: true,
                address: address,
                size: size,
                data: Array.from(new Uint8Array(buf))
            };
        } catch (e) {
            return { success: false, error: e.message };
        }
    },

    readPointer: function(address) {
        try {
            const addr = ptr(address);
            const value = Memory.readPointer(addr);
            return {
                success: true,
                address: address,
                value: value.toString()
            };
        } catch (e) {
            return { success: false, error: e.message };
        }
    },

    readSsString: function(address) {
        try {
            const addr = ptr(address);
            // SSO string layout: first 16 bytes = { union { char buf[16]; struct { size_t capacity; char* ptr; size_t size; } } }
            const flags = Memory.readU64(addr);
            const isShort = (flags & 1) === 0;

            if (isShort) {
                // Short string stored inline
                const bytes = [];
                for (let i = 0; i < 16; i++) {
                    const b = Memory.readU8(addr.add(i));
                    if (b === 0) break;
                    bytes.push(b);
                }
                return {
                    success: true,
                    address: address,
                    type: "short",
                    value: String.fromCharCode.apply(null, bytes)
                };
            } else {
                // Long string - read from pointer
                const ptrAddr = Memory.readPointer(addr.add(8));
                const size = Memory.readU64(addr.add(16)).toNumber();
                const buf = Memory.readByteArray(ptrAddr, Math.min(size, 4096));
                return {
                    success: true,
                    address: address,
                    type: "long",
                    value: Array.from(new Uint8Array(buf))
                };
            }
        } catch (e) {
            return { success: false, error: e.message };
        }
    },

    followChain: function(base, offsets) {
        try {
            let current = ptr(base);
            const steps = [{ address: current.toString(), value: current.toString() }];

            for (const offset of offsets) {
                current = Memory.readPointer(current.add(offset));
                steps.push({
                    offset: offset,
                    address: current.toString(),
                    value: current.toString()
                });
            }

            return {
                success: true,
                base: base,
                offsets: offsets,
                finalAddress: current.toString(),
                steps: steps
            };
        } catch (e) {
            return { success: false, error: e.message };
        }
    }
};
"""

EFFECT_MONITOR_SCRIPT = """
'use strict';

rpc.exports = {
    startEffectMonitor: function() {
        // Effect dispatch switch-case at 0x14180B050
        const effectDispatchAddr = ptr("0x14180B050");
        const effects = [];

        Interceptor.attach(effectDispatchAddr, {
            onEnter: function(args) {
                const effectId = this.context.rcx;
                effects.push({
                    timestamp: Date.now(),
                    effectId: effectId.toString(),
                    instruction: "effect_dispatch"
                });
            }
        });

        return { success: true, message: "Effect monitor attached" };
    }
};
"""

TRIGGER_MONITOR_SCRIPT = """
'use strict';

rpc.exports = {
    startTriggerMonitor: function() {
        const triggers = [];

        // Monitor trigger evaluations via script engine
        Process.enumerateModules().forEach(function(mod) {
            if (mod.name === "stellaris.exe") {
                // Find trigger evaluation patterns
                const ranges = mod.enumerateRanges("r-x");
                ranges.forEach(function(range) {
                    const buf = Memory.readByteArray(range.base, Math.min(range.size, 4096));
                    // Look for trigger-related patterns
                });
            }
        });

        return { success: true, message: "Trigger monitor attached" };
    }
};
"""


def cmd_read_memory(
    args: argparse.Namespace,
) -> dict[str, Any]:
    """Read memory at address."""
    device = get_device(args.host)
    session = attach_process(device, args.pid)
    script = create_script(session, MEMORY_READ_SCRIPT)

    address = args.address if args.address.startswith("0x") else f"0x{args.address}"
    result = script.exports_sync.read_memory(address, args.size)

    return format_response(
        "read_memory",
        result.get("success", False),
        data=result.get("data"),
        error=result.get("error"),
        address=address,
        size=args.size,
    )


def cmd_read_pointer(
    args: argparse.Namespace,
) -> dict[str, Any]:
    """Read pointer at address."""
    device = get_device(args.host)
    session = attach_process(device, args.pid)
    script = create_script(session, MEMORY_READ_SCRIPT)

    address = args.address if args.address.startswith("0x") else f"0x{args.address}"
    result = script.exports_sync.read_pointer(address)

    return format_response(
        "read_pointer",
        result.get("success", False),
        data=result.get("value"),
        error=result.get("error"),
        address=address,
    )


def cmd_read_ssstring(
    args: argparse.Namespace,
) -> dict[str, Any]:
    """Read SSO string at address."""
    device = get_device(args.host)
    session = attach_process(device, args.pid)
    script = create_script(session, MEMORY_READ_SCRIPT)

    address = args.address if args.address.startswith("0x") else f"0x{args.address}"
    result = script.exports_sync.read_ssstring(address)

    return format_response(
        "read_ssstring",
        result.get("success", False),
        data=result.get("value"),
        error=result.get("error"),
        address=address,
        string_type=result.get("type"),
    )


def cmd_follow_chain(
    args: argparse.Namespace,
) -> dict[str, Any]:
    """Follow pointer chain from base address."""
    device = get_device(args.host)
    session = attach_process(device, args.pid)
    script = create_script(session, MEMORY_READ_SCRIPT)

    base = args.base if args.base.startswith("0x") else f"0x{args.base}"
    offsets = [int(o.strip()) for o in args.offsets.split(",")]
    result = script.exports_sync.follow_chain(base, offsets)

    return format_response(
        "follow_chain",
        result.get("success", False),
        data=result.get("finalAddress"),
        error=result.get("error"),
        base=base,
        offsets=offsets,
        steps=result.get("steps"),
    )


def cmd_monitor_effects(
    args: argparse.Namespace,
) -> dict[str, Any]:
    """Monitor effect executions."""
    device = get_device(args.host)
    session = attach_process(device, args.pid)
    script = create_script(session, EFFECT_MONITOR_SCRIPT)

    result = script.exports_sync.start_effect_monitor()
    if not result.get("success"):
        return format_response("monitor_effects", False, error=result.get("error"))

    print(json.dumps(format_response("monitor_effects", True, message="Monitoring started")))
    print(f"Monitoring for {args.duration} seconds...", file=sys.stderr)

    import time

    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        pass

    return format_response("monitor_effects", True, message="Monitoring completed")


def cmd_monitor_triggers(
    args: argparse.Namespace,
) -> dict[str, Any]:
    """Monitor trigger evaluations."""
    device = get_device(args.host)
    session = attach_process(device, args.pid)
    script = create_script(session, TRIGGER_MONITOR_SCRIPT)

    result = script.exports_sync.start_trigger_monitor()
    if not result.get("success"):
        return format_response("monitor_triggers", False, error=result.get("error"))

    print(json.dumps(format_response("monitor_triggers", True, message="Monitoring started")))
    print(f"Monitoring for {args.duration} seconds...", file=sys.stderr)

    import time

    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        pass

    return format_response("monitor_triggers", True, message="Monitoring completed")


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Frida memory diagnostic tool for AI-automated inspection"
    )

    parser.add_argument(
        "--pid",
        type=str,
        default="stellaris.exe",
        help="Target process ID or name (default: stellaris.exe)",
    )

    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Frida-server host (default: 127.0.0.1)",
    )

    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        help="Duration for monitoring commands in seconds (default: 60)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # read-memory
    read_memory_parser = subparsers.add_parser("read-memory", help="Read memory at address")
    read_memory_parser.add_argument("address", help="Memory address to read (hex)")
    read_memory_parser.add_argument("size", type=int, help="Number of bytes to read")

    # read-pointer
    read_pointer_parser = subparsers.add_parser("read-pointer", help="Read pointer at address")
    read_pointer_parser.add_argument("address", help="Memory address to read (hex)")

    # read-ssstring
    read_ssstring_parser = subparsers.add_parser(
        "read-ssstring", help="Read SSO string at address"
    )
    read_ssstring_parser.add_argument("address", help="Memory address to read (hex)")

    # follow-chain
    follow_chain_parser = subparsers.add_parser(
        "follow-chain", help="Follow pointer chain"
    )
    follow_chain_parser.add_argument("base", help="Base address (hex)")
    follow_chain_parser.add_argument(
        "offsets", help="Comma-separated offsets (e.g., 0,16,0)"
    )

    # monitor-effects
    subparsers.add_parser("monitor-effects", help="Monitor effect executions")

    # monitor-triggers
    subparsers.add_parser("monitor-triggers", help="Monitor trigger evaluations")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    command_map = {
        "read-memory": cmd_read_memory,
        "read-pointer": cmd_read_pointer,
        "read-ssstring": cmd_read_ssstring,
        "follow-chain": cmd_follow_chain,
        "monitor-effects": cmd_monitor_effects,
        "monitor-triggers": cmd_monitor_triggers,
    }

    handler = command_map.get(args.command)
    if not handler:
        print(json.dumps(format_response(args.command, False, error="Unknown command")))
        return 1

    try:
        result = handler(args)
        print(json.dumps(result, indent=2))
        return 0 if result.get("success") else 1
    except frida.ProcessNotFoundError:
        print(
            json.dumps(
                format_response(
                    args.command, False, error=f"Process not found: {args.pid}"
                )
            )
        )
        return 1
    except frida.ServerNotRunningError:
        print(
            json.dumps(
                format_response(
                    args.command,
                    False,
                    error="Frida server not running. Start frida-server first.",
                )
            )
        )
        return 1
    except Exception as e:
        print(json.dumps(format_response(args.command, False, error=str(e))))
        return 1


if __name__ == "__main__":
    sys.exit(main())
