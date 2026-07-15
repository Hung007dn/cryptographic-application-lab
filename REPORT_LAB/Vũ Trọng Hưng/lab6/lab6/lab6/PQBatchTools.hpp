// PQBatchTools.hpp
#pragma once

#include "PQConfig.hpp"

#include <cstddef>

class PQBatchTools {
public:
    static bool runBatchVerifyDemo(PQAlgorithm algo, std::size_t count);
    static bool runBatchDecapsulationTiming(PQAlgorithm algo, std::size_t count);
};
