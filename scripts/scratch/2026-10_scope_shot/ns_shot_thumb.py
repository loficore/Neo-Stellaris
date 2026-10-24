"""One-off: shrink the daemon's window shot so it fits the base64 slice channel.

    python ns_shot_thumb.py <src.png> <dst.jpg> <width> <quality>

The slice channel (pull_slice.sh / ns_pull.py) carries 525 bytes per ssh call, so a
3 MB native-resolution PNG is not pullable; a 720 px JPEG is. Nothing is uploaded.
"""

import sys

from PIL import Image


def main():
    src, dst, width, quality = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
    im = Image.open(src).convert("RGB")
    height = max(1, round(im.height * width / im.width))
    im.resize((width, height), Image.LANCZOS).save(dst, "JPEG", quality=quality)
    print("THUMB", dst, Image.open(dst).size)
    return 0


if __name__ == "__main__":
    sys.exit(main())
