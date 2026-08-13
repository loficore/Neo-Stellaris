#!/usr/bin/env python3
"""
Frida connection test for Stellaris reverse engineering.

Tests connection to frida-server and attaches to stellaris.exe.
Requires:
- frida-server running on Windows
- SSH tunnel: ssh -L 27042:127.0.0.1:27042 user@windows-machine
- pip install frida frida-tools
"""

import sys
import frida


def get_device(host: str = "127.0.0.1", port: int = 27042) -> frida.core.Device:
    """Get frida device (local or remote)."""
    try:
        if host == "127.0.0.1" and port == 27042:
            # Try local first
            print("[*] Trying local device...")
            device = frida.get_local_device()
            print(f"[+] Local device: {device.name}")
            return device
        else:
            # Remote connection
            print(f"[*] Connecting to remote device at {host}:{port}...")
            manager = frida.get_device_manager()
            device = manager.add_remote_device(f"{host}:{port}")
            print(f"[+] Remote device: {device.name}")
            return device
    except Exception as e:
        print(f"[-] Failed to get device: {e}")
        print("[!] Ensure frida-server is running and accessible.")
        sys.exit(1)


def find_stellaris(device: frida.core.Device) -> int | None:
    """Find stellaris.exe process and return PID."""
    print("[*] Enumerating processes...")
    processes = device.enumerate_processes()

    stellaris_procs = [
        p for p in processes if "stellaris" in p.name.lower()
    ]

    if not stellaris_procs:
        print("[-] stellaris.exe not found!")
        print("[*] Available processes containing 'stellar':")
        for p in processes:
            if "stellar" in p.name.lower():
                print(f"    PID {p.pid}: {p.name}")
        return None

    proc = stellaris_procs[0]
    print(f"[+] Found: {proc.name} (PID: {proc.pid})")
    return proc.pid


def attach_to_process(device: frida.core.Device, pid: int) -> frida.core.Session:
    """Attach to process and return session."""
    print(f"[*] Attaching to PID {pid}...")
    try:
        session = device.attach(pid)
        print(f"[+] Attached successfully!")
        print(f"    Session ID: {session.pid}")
        return session
    except frida.ProcessNotFoundError:
        print(f"[-] Process {pid} not found (may have exited)")
        sys.exit(1)
    except frida.PermissionDeniedError:
        print(f"[-] Permission denied. Run as Administrator.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Attach failed: {e}")
        sys.exit(1)


def test_injection(session: frida.core.Session) -> bool:
    """Test basic script injection."""
    print("[*] Testing script injection...")

    test_script = """
    rpc.exports = {
        getVersion: function() {
            return Process.platform + ' ' + Process.arch;
        },
        getModules: function() {
            return Process.enumerateModules()
                .slice(0, 5)
                .map(m => m.name);
        }
    };
    """

    try:
        script = session.create_script(test_script)
        script.load()

        # Call RPC exports
        version = script.exports_sync.get_version()
        print(f"[+] Platform: {version}")

        modules = script.exports_sync.get_modules()
        print(f"[+] First 5 modules: {', '.join(modules)}")

        script.unload()
        print("[+] Injection test passed!")
        return True
    except Exception as e:
        print(f"[-] Injection test failed: {e}")
        return False


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Test Frida connection to Stellaris"
    )
    parser.add_argument(
        "-H", "--host",
        default="127.0.0.1",
        help="frida-server host (default: 127.0.0.1)"
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=27042,
        help="frida-server port (default: 27042)"
    )
    parser.add_argument(
        "--pid",
        type=int,
        default=None,
        help="Attach to specific PID instead of searching"
    )
    parser.add_argument(
        "--detach",
        action="store_true",
        help="Detach after successful test (don't keep session open)"
    )

    args = parser.parse_args()

    print("=" * 50)
    print("  Frida Connection Test - Stellaris RE")
    print("=" * 50)
    print()

    # Get device
    device = get_device(args.host, args.port)

    # Find or use specified PID
    if args.pid:
        pid = args.pid
        print(f"[*] Using specified PID: {pid}")
    else:
        pid = find_stellaris(device)
        if pid is None:
            print()
            print("[!] Please start stellaris.exe first, or specify PID with --pid")
            sys.exit(1)

    # Attach
    session = attach_to_process(device, pid)

    # Test injection
    success = test_injection(session)

    if args.detach or success:
        print()
        if args.detach:
            print("[*] Detaching...")
            session.detach()
            print("[+] Detached.")
        else:
            print("[*] Session kept open. Press Enter to detach...")
            try:
                input()
                session.detach()
                print("[+] Detached.")
            except KeyboardInterrupt:
                print()
                session.detach()
                print("[+] Detached.")

    print()
    print("[+] Test complete!")
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
