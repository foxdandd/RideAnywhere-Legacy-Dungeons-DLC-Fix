# RideAnywhere Legacy Dungeons DLC Fix — source

This directory contains the source and build helpers for the additional
runtime patch used by the RideAnywhere Legacy Dungeons/DLC fix.

It is intentionally **source-only**.  It does not include the original
RideAnywhere binary, game map assets, release archives, or save files.

## What is included

- `src/RideAnywhereSpecialAreaFix.c` — the x64 helper DLL source.
- `tools/Build-RuntimeFix.ps1` — reproducible TinyCC build script.
- `tools/Patch-RideAnywhereSignature.ps1` — build-time byte patcher for a
  locally supplied RideAnywhere DLL.

## Runtime behavior

The helper runs inside the Elden Ring process.  It scans executable sections
of the current game image for the two Torrent permission gates and replaces
the matching instructions in memory.  It retries while the game image is
initializing and skips itself when the original `RideAnywhere.dll` is already
loaded (the 1.16.2 load order).

The helper source contains no network, registry, file-I/O, persistence,
credential, or remote-process APIs.  Its intentional sensitive operation is
in-process executable-memory patching via `VirtualProtect`, which can trigger
antivirus heuristics.  Keep Microsoft Defender enabled; do not add exclusions
or disable protection to run an unreviewed binary.

## Build the helper

1. Obtain an x64 TinyCC toolchain from a trusted, official source.  This
   repository does not bundle a compiler or a prebuilt DLL.
2. Put `tcc.exe` under `toolchain/tcc/`, or pass `-TccRoot` explicitly.
3. Run:

   ```powershell
   pwsh -File .\tools\Build-RuntimeFix.ps1
   ```

   The output is written to `dist/RideAnywhereSpecialAreaFix.dll` and its
   SHA-256 is printed by the script.

## Patch a locally supplied RideAnywhere DLL

The original RideAnywhere DLL is not distributed here.  Make a backup and
run the patcher against a copy obtained under the original mod's terms:

```powershell
pwsh -File .\tools\Patch-RideAnywhereSignature.ps1 `
  -DllPath 'C:\path\to\RideAnywhere.dll' `
  -GameVersion 1.17
```

The patcher only reads and rewrites the specified local DLL, requires a
unique signature match, and verifies the resulting signature and patch bytes.

## Published artifact reference

The source was used to build the helper in the published 1.0.9 package.  The
binary is deliberately not included in this source directory:

- `RideAnywhereSpecialAreaFix.dll` SHA-256:
  `D8489049D8A387A6DBA651F1E8C3169E588099C134F42E34A4C094B6E50B3A34`
- Universal ZIP SHA-256:
  `2DBA7B9411C6B6ABF560E04EA13F68C2DD2C73748F99ABC8198A1A434A4C0F9E`

## Credits and redistribution

RideAnywhere, Torrent in Legacy Dungeons, Elden Ring, and their assets belong
to their respective authors and rights holders.  Follow the original mod
authors' permissions and Nexus rules.  Do not copy the original DLL or game
map files into this repository; link to the original mods instead.
