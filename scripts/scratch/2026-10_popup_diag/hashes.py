"""sha256 of the batch's remote artifacts, one short line each."""
import hashlib

PATHS = [
    r"C:\temp\ns_game_log.jsonl",
    r"C:\temp\ns_awake_status.json",
    r"C:\temp\ns_game_shot.png",
    r"C:\temp\game_supervisor.py",
    r"C:\temp\popup_ocr.py",
    r"C:\temp\popup_guard.py",
    r"C:\temp\popup_identity.py",
]
for p in PATHS:
    try:
        with open(p, "rb") as f:
            h = hashlib.sha256(f.read()).hexdigest()
    except OSError as exc:
        h = "ERR %s" % exc.__class__.__name__
    print(p.replace("C:\\temp\\", ""), h[:16])
