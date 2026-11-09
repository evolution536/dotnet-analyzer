#pragma once

// Represents error codes thrown by the analyzer.
enum class error_codes
{
	success,
	insufficient_buffer,
	invalid_dos_signature,
	invalid_pe_signature,
	invalid_image_type,
	invalid_cli_header,
	invalid_metadata_directory,
	invalid_stream_header,
	heap_out_of_bounds,
	decoded_index_invalid_table,
	invalid_method_header,
	invalid_method_rva,
};

// Gets friendly representation of error message.
const char* get_error_code_message(const error_codes err);