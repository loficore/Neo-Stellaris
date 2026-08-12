# Embedding Deno's V8 Runtime in a C++ DLL for Windows

Research compiled for the Stellaris RE project. Answer to the question:
"Can we host a JavaScript engine (V8/Deno) inside a C++ DLL for Windows to
extend the Clausewitz (augustus) mod system?"

## Executive Summary

- **Yes, V8 can be embedded in a Windows DLL**, but V8 is a static library
  (monolith) intended for static linking into a host EXE, not a standalone DLL.
  To expose a scripting host you build YOUR OWN DLL that statically links V8
  and exports your own C ABI functions.
- **Deno's runtime is Rust-based (deno_core/JsRuntime)** — it cannot be linked
  directly from C++. You either (a) embed raw V8 via its C++ API, (b) build a
  `cdylib` in Rust using deno_core, or (c) use Deno's FFI to call INTO a DLL
  (opposite direction — Deno is the host).
- For a game-modding use case (this project), **QuickJS is the pragmatic
  choice**: ~1 MB footprint, ~300 µs startup, trivially embeddable C API, and
  used by real game/plugin systems (CS2 Plugify, GodotJS, etc.).

## Evidence sections
Full details with permalinks in the analysis doc (see `analysis/`).
