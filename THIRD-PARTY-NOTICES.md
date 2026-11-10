# Third-party notices

Neo-Stellaris itself is MIT licensed (see `LICENSE`). The components below
carry their own terms; this file records which of them travel with a shipped
artifact and which only exist at build time.

## QuickJS — shipped

`libs/quickjs/` is QuickJS by Fabrice Bellard and Charlie Gordon, MIT licensed.
The full text is `libs/quickjs/LICENSE`, and that file is included verbatim in
the developer preview zip: the DLL embeds QuickJS, so the licence has to travel
with the bytes.

Changes made in this tree are limited to the build/UB fixes upstream needs to
compile as part of the host (see `docs/offline-tooling.md` and the `§47`/`§48`
entries of the runtime evidence volumes); the upstream license is unchanged.

## VitePress — build time only

The documentation site under `site/` is built with VitePress (MIT), pinned to
an exact version in `site/package.json`. It is a build-time dependency of the
website only: no VitePress code is part of the DLL, `inject.exe`, the SDK, or
the preview zip.

## Other Zig / C dependencies — not redistributed

Everything else the host builds against is either part of the Zig standard
library (linked into our own artifact, not redistributed separately) or a
system library the game already provides. No third-party binaries are
redistributed by this repository beyond the QuickJS source above.

Stellaris and the Clausewitz engine are trademarks of Paradox Interactive.
This project is not affiliated with or endorsed by Paradox Interactive.
