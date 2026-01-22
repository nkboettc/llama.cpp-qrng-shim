#pragma once
#include <cstdint>

namespace qrng {
    // initialize (seed used for fallback PRNG only)
    void   init(uint32_t seed);
    // uniform in [0,1)
    float  rand01();
    // no-op placeholder
    void   shutdown();
}
