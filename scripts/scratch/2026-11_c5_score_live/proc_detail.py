"""One-off (2026-11-03): every stellaris.exe with the DLLs we inject.

`wait_for_process` takes any stellaris.exe, so a stale process from an earlier
window can absorb an injection (2026-11-03: two processes, the real one never got
the DLL and logged `Invalid scripted effect: neo_action`).  This prints enough to
tell them apart before and after a shot.
"""
import psutil


def main() -> None:
    found = 0
    for proc in psutil.process_iter(["pid", "name", "create_time", "cmdline"]):
        if (proc.info["name"] or "").lower() != "stellaris.exe":
            continue
        found += 1
        print(f"pid={proc.info['pid']} created={int(proc.info['create_time'])} "
              f"cmdline={proc.info['cmdline']}")
        try:
            modules = [m.path for m in proc.memory_maps() if "sqjs" in m.path.lower()
                       or "quickjs" in m.path.lower()]
        except Exception as exc:  # noqa: BLE001 - one-off diagnostic
            print(f"  modules=UNREADABLE {exc}")
            continue
        print(f"  injected={modules}")
    print(f"stellaris_count={found}")


if __name__ == "__main__":
    main()
