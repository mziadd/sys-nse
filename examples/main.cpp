// Minimal usage example for sys-nse.
//
// This example prints the raw integer mask returned by the probe.
#include "sys_nse.h"

#include <cstdint>
#include <iostream>

int main() {
  const uint32_t mask = sys_nse::sys_rt_p1_validate();
  std::cout << mask << std::endl;
  return 0;
}

