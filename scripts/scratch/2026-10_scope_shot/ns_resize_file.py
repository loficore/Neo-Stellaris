"""Host-side helper: shrink an existing screenshot FILE to a small JPEG.

ImageGrab from an ssh session dies with "OSError: screen grab failed" — that
session has no interactive desktop, so the grab itself must stay inside the
supervisor (C:/temp/ns_game_shot.png). This helper only re-encodes that file so
it fits the base64 slice channel that pulls it back.

    python ns_resize_file.py [in] [out] [width] [quality]
"""

import os
import sys

from PIL import Image


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else r"C:\temp\ns_game_shot.png"
    out = sys.argv[2] if len(sys.argv) > 2 else r"C:\temp\ns_shot_small.jpg"
    width = int(sys.argv[3]) if len(sys.argv) > 3 else 960
    quality = int(sys.argv[4]) if len(sys.argv) > 4 else 45

    img = Image.open(src).convert("RGB")
    w, h = img.size
    if width < w:
        img = img.resize((width, int(h * width / w)), Image.LANCZOS)
    img.save(out, "JPEG", quality=quality, optimize=True)
    print("SRC", (w, h), "OUT", img.size, "PATH", out,
          "BYTES", os.path.getsize(out))


if __name__ == "__main__":
    main()
