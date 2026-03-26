// Native integrity checks (user-space probes).
//
// Why a dedicated header?
// - In the app, this function is also declared by `sys_runtime.h` for convenience.
// - For open source, we keep NSE independent from any private runtime tables.
#pragma once

#include <cstdint>

namespace sys_nse {

// Integrity signals bitmask.
// Returns a raw integer mask; the caller can interpret bits.
uint32_t sys_rt_p1_validate();

} // namespace sys_nse

