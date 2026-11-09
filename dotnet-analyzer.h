#pragma once

#include "error.h"
#include "analysis-result.h"

// Used to parse .NET files and analyze them.
class dotnet_analyzer
{
private:
	const uint8_t* buffer;
	uint32_t buffer_len;
	error_codes last_error_code;

	// Pointer to the analysis result, created by the analyzer dynamically.
	analysis_result* result;
public:
	dotnet_analyzer(const uint8_t* buffer, const uint32_t size);
	~dotnet_analyzer();

	error_codes get_last_error() const;
	bool run();

	analysis_result* get_analysis_result() const;
};