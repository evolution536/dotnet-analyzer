#pragma once

#include <cstdint>
#include "error.h"
#include "analysis-result.h"

// Parses method header amd body.
const error_codes parse_method_header_body(analysis_result* result, const uint32_t rva, method& out_method);