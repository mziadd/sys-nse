// Native integrity checks used by the mobile app bridge.
//
// Notes:
// - These are user-space probes (filesystem + /proc + env). Not kernel-level.
// - Treat results as signals. They are best-effort heuristics.
//
// Open-source extraction:
// - This file intentionally does NOT include any app-specific runtime tables.
// - It only depends on `sys_utils.h` and standard/OS headers.
#include "sys_nse.h"
#include "sys_utils.h"

#include <cstdio>
#include <cstring>
#include <string>

#include <unistd.h>
#include <sys/stat.h>

#ifdef __ANDROID__
#include <sys/system_properties.h>
#endif

#ifdef __APPLE__
#include <TargetConditionals.h>
#include <sys/sysctl.h>
#endif

using namespace sys_utils;

namespace sys_nse {

/**
 * [NSE] - Core Native Security Engine (NSE) implementation.
 * Performs native user-space integrity probes and runtime auditing.
 * This is NOT a kernel module. Signals are best-effort heuristics.
 */
uint32_t sys_rt_p1_validate() {
  uint32_t mask = 0;

  // 1. [FS PROBE] - Standard Root/Magisk Paths
  // p1: /system/bin/su
  const unsigned char p1[] = {0x83, 0xdf, 0xd5, 0xdf, 0xd8, 0xc9, 0xc1, 0x83, 0xce, 0xc5, 0xc2, 0x83, 0xdf, 0xd9};
  // p2: /system/xbin/su
  const unsigned char p2[] = {0x83, 0xdf, 0xd5, 0xdf, 0xd8, 0xc9, 0xc1, 0x83, 0xd4, 0xce, 0xc5, 0xc2, 0x83, 0xdf, 0xd9};
  // p3: /sbin/su
  const unsigned char p3[] = {0x83, 0xdf, 0xce, 0xc5, 0xc2, 0x83, 0xdf, 0xd9};
  // pmagisk: /system/xbin/magisk
  const unsigned char p4[] = {0x83, 0xdf, 0xd5, 0xdf, 0xd8, 0xc9, 0xc1, 0x83, 0xd4, 0xce, 0xc5, 0xc2, 0x83, 0xc1, 0xcd, 0xcb, 0xc5, 0xdf, 0xc7};

  auto chk = [&](const unsigned char* b, size_t l) { return access(d(b, l).c_str(), F_OK) == 0; };

  if (chk(p1, 14) || chk(p2, 15) || chk(p3, 8) || chk(p4, 19)) mask |= 0x1;

  // 2. [PROC PROBE] - /proc/self/status -> TracerPid
  const unsigned char f1[] = {0x83, 0xdc, 0xde, 0xc3, 0xcf, 0x83, 0xdf, 0xc9, 0xc0, 0xca, 0x83, 0xdf, 0xd8, 0xcd, 0xd8, 0xd9, 0xdf}; // "/proc/self/status"
  const unsigned char s1[] = {0xf8, 0xde, 0xcd, 0xcf, 0xc9, 0xde, 0xfc, 0xc5, 0xc8, 0x96}; // "TracerPid:"

  FILE* status = fopen(d(f1, 17).c_str(), "r");
  if (status) {
    char line[512];
    std::string s_match = d(s1, 10);
    while (fgets(line, sizeof(line), status)) {
      if (strncmp(line, s_match.c_str(), 10) == 0) {
        int pid = 0;
        const char* colon = strchr(line, ':');
        if (colon != nullptr) {
          const char* p = colon + 1;
          while (*p == ' ' || *p == '\t') ++p;
          pid = atoi(p);
        }
        if (pid > 0) { mask |= 0x2; break; }
      }
    }
    fclose(status);
  }

  // 3. [MAP PROBE] - /proc/self/maps -> Frida, Xposed, Magisk, Zygisk, Riru, etc.
  if (mask == 0) {
    const unsigned char f2[] = {0x83, 0xdc, 0xde, 0xc3, 0xcf, 0x83, 0xdf, 0xc9, 0xc0, 0xca, 0x83, 0xc1, 0xcd, 0xdc, 0xdf}; // "/proc/self/maps"
    FILE* maps = fopen(d(f2, 15).c_str(), "r");
    if (maps) {
      char line[1024];

      // Token 0 decodes to: "frida-agent" (Primary Frida payload)
      const unsigned char t0[] = {0xca, 0xde, 0xc5, 0xc8, 0xcd, 0x81, 0xcd, 0xcb, 0xc9, 0xc2, 0xd8};
      // Token 1 decodes to: "frida-gadget" (Frida embedded library)
      const unsigned char t1[] = {0xca, 0xde, 0xc5, 0xc8, 0xcd, 0x81, 0xcb, 0xcd, 0xc8, 0xcb, 0xc9, 0xd8};
      // Token 2 decodes to: "libfrida" (Generic Frida reference)
      const unsigned char t2[] = {0xc0, 0xc5, 0xce, 0xca, 0xde, 0xc5, 0xc8, 0xcd};
      // Token 3 decodes to: "libsubstrate.so" (Cydia Substrate engine)
      const unsigned char t3[] = {0xc0, 0xc5, 0xce, 0xdf, 0xd9, 0xce, 0xdf, 0xd8, 0xde, 0xcd, 0xd8, 0xc9, 0x82, 0xdf, 0xc3};
      // Token 4 decodes to: "libxposed" (Xposed framework core)
      const unsigned char t4[] = {0xc0, 0xc5, 0xce, 0xd4, 0xdc, 0xc3, 0xdf, 0xc9, 0xc8};
      // Token 5 decodes to: "xposed.dex" (Xposed secondary stage)
      const unsigned char t5[] = {0xd4, 0xdc, 0xc3, 0xdf, 0xc9, 0xc8, 0x82, 0xc8, 0xc9, 0xd4};
      // Token 6 decodes to: "libxposed_art.so" (Xposed ART bridge)
      const unsigned char t6[] = {0xc0, 0xc5, 0xce, 0xd4, 0xdc, 0xc3, 0xdf, 0xc9, 0xc8, 0xf3, 0xcd, 0xde, 0xd8, 0x82, 0xdf, 0xc3};
      // Token 7 decodes to: "magisk" (Magisk root hiding/management)
      const unsigned char t7[] = {0xc1, 0xcd, 0xcb, 0xc5, 0xdf, 0xc7};
      // Token 8 decodes to: "zygisk" (Zygote-level Magisk engine)
      const unsigned char t8[] = {0xd6, 0xd5, 0xcb, 0xc5, 0xdf, 0xc7};
      // Token 9 decodes to: "riru" (Riru core injection module)
      const unsigned char t9[] = {0xde, 0xc5, 0xde, 0xd9};
      const unsigned char t10[] = {0xc0, 0xdf, 0xdc, 0xc3, 0xdf, 0xc9, 0xc8}; // "lsposed"
      const unsigned char t11[] = {0xc9, 0xc8, 0xd4, 0xdc}; // "edxp"
      const unsigned char t12[] = {0xdf, 0xcd, 0xc2, 0xc8, 0xc4, 0xc3, 0xc3, 0xc7}; // "sandhook"
      const unsigned char t13[] = {0xc8, 0xc9, 0xd4, 0xdc, 0xc3, 0xdf, 0xc9, 0xc8}; // "dexposed"

      const std::string p_set[] = {
        d(t0, 11), d(t1, 12), d(t2, 8), d(t3, 15), d(t4, 9), d(t5, 10),
        d(t6, 16), d(t7, 6), d(t8, 6), d(t9, 4), d(t10, 7), d(t11, 4),
        d(t12, 8), d(t13, 8)
      };

      while (fgets(line, sizeof(line), maps)) {
        for (const auto& needle : p_set) {
          if (strstr(line, needle.c_str()) != nullptr) { mask |= 0x4; break; }
        }
        if (mask & 0x4) break;
      }
      fclose(maps);
    }
  }

#ifdef __ANDROID__
  // 5. [PROP PROBE] - ro.debuggable, ro.secure, ro.kernel.qemu
  char prop_val[256];
  const unsigned char pr1[] = {0xde, 0xc3, 0x82, 0xc8, 0xc9, 0xce, 0xd9, 0xcb, 0xcb, 0xcd, 0xce, 0xc0, 0xc9}; // "ro.debuggable"
  const unsigned char pr2[] = {0xde, 0xc3, 0x82, 0xdf, 0xc9, 0xcf, 0xd9, 0xde, 0xc9}; // "ro.secure"
  const unsigned char em1[] = {0xde, 0xc3, 0x82, 0xc7, 0xc9, 0xde, 0xc2, 0xc9, 0xc0, 0x82, 0xdd, 0xc9, 0xc1, 0xd9}; // "ro.kernel.qemu"

  const bool hasStrongEvidence = (mask & (0x1 | 0x2 | 0x4)) != 0;
  if (hasStrongEvidence) {
    if (__system_property_get(d(pr1, 13).c_str(), prop_val) > 0 && prop_val[0] == '1') mask |= 0x10;
    if (__system_property_get(d(pr2, 9).c_str(), prop_val) > 0 && prop_val[0] == '0') mask |= 0x10;
  }
  if (__system_property_get(d(em1, 14).c_str(), prop_val) > 0 && prop_val[0] == '1') mask |= 0x20;

  // 6. [SELINUX PROBE] - /sys/fs/selinux/enforce (Check if permissive)
  const unsigned char se1[] = {0x83, 0xDF, 0xD5, 0xDF, 0x83, 0xCA, 0xDF, 0x83, 0xDF, 0xC9, 0xC0, 0xC5, 0xC2, 0xD9, 0xD4, 0x83, 0xC9, 0xC2, 0xCA, 0xC3, 0xDE, 0xCF, 0xC9};
  FILE* selinux = fopen(d(se1, 23).c_str(), "r");
  if (selinux) {
    int enforcing = fgetc(selinux);
    if (enforcing == '0' && hasStrongEvidence) mask |= 0x80;
    fclose(selinux);
  }
#endif

#ifdef __APPLE__
  // iOS-specific signals.
#if TARGET_OS_SIMULATOR
  mask |= 0x40;
#endif
  // DYLD_INSERT_LIBRARIES is commonly used for injection in debug/test contexts too.
  const unsigned char dy1[] = {0xe8, 0xf5, 0xe0, 0xe8, 0xf3, 0xe5, 0xe2, 0xff, 0xe9, 0xfe, 0xf8, 0xf3, 0xe0, 0xe5, 0xee, 0xfe, 0xed, 0xfe, 0xe5, 0xe9, 0xff};
  if (getenv(d(dy1, 21).c_str()) != nullptr) mask |= 0x100;

  // Known jailbreak-related paths (heuristic).
  const unsigned char ip1[] = {0x83, 0xe0, 0xc5, 0xce, 0xde, 0xcd, 0xde, 0xd5, 0x83, 0xe1, 0xc3, 0xce, 0xc5, 0xc0, 0xc9, 0xff, 0xd9, 0xce, 0xdf, 0xd8, 0xde, 0xcd, 0xd8, 0xc9, 0x83, 0xe1, 0xc3, 0xce, 0xc5, 0xc0, 0xc9, 0xff, 0xd9, 0xce, 0xdf, 0xd8, 0xde, 0xcd, 0xd8, 0xc9, 0x82, 0xc8, 0xd5, 0xc0, 0xc5, 0xce};
  const unsigned char ip2[] = {0x83, 0xed, 0xdc, 0xdc, 0xc0, 0xc5, 0xcf, 0xcd, 0xd8, 0xc5, 0xc3, 0xc2, 0xdf, 0x83, 0xef, 0xd5, 0xc8, 0xc5, 0xcd, 0x82, 0xcd, 0xdc, 0xdc};

  if (chk(ip1, 46) || chk(ip2, 23)) mask |= 0x200;
#endif

  return mask;
}

} // namespace sys_nse

