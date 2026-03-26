# sys-nse (Native Security Engine - user-space probes)

This module contains a small, standalone C++ implementation that performs **best-effort user-space integrity probes** (filesystem + `/proc` + environment).

It is designed to be embedded into mobile apps (Android NDK / iOS) or any Linux/macOS process that wants lightweight runtime tamper signals.

## What it does

- Scans for common root/jailbreak artifacts (paths)
- Checks for debugger attachment signals (`/proc/self/status` → `TracerPid`)
- Checks loaded mappings (`/proc/self/maps`) for common injection frameworks (Frida, Xposed, Magisk, etc.)
- Android-only: reads system properties for additional signals
- Apple-only: simulator + `DYLD_INSERT_LIBRARIES` heuristic + jailbreak path probes

The output is a raw integer bitmask.

## Build (CMake)

From the module root:

```bash
cmake -S . -B build
cmake --build build -j
./build/sys_nse_example
```

## Usage

```cpp
#include "sys_nse.h"

uint32_t mask = sys_nse::sys_rt_p1_validate();
```

## Notes

- This is **heuristic** detection. Treat it as a signal, not proof.
- `/proc` checks are only meaningful on Linux/Android.

