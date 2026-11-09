#pragma once

#include <map>
#include <string>
#include "analysis-result.h"

// FIXME: esscap string funct


// Dumps the entire #Strings stream, which contains null-terminated, ASCII strings.
bool dump_strings_stream(const analysis_result* result, std::map<uint32_t, std::string>& dumped_strings);

// Dumps the entire #US stream, which contains null-terminated, UTF-16 strings.
bool dump_unicode_strings_stream(const analysis_result* result, std::map<uint32_t, std::string>& dumped_strings);

// Dumps the entire #Blob stream containing signatures and more.
bool dump_blob_stream(const analysis_result* result, std::map<uint32_t, std::string>& dumped_blobs);