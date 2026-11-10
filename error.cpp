#include <cstddef>
#include "error.h"

// Gets friendly representation of error message.
const char* get_error_code_message(const error_codes err)
{
	switch (err)
	{
		case error_codes::success:
			return "Success";
		case error_codes::insufficient_buffer:
			return "Insufficient buffer";
		case error_codes::invalid_dos_signature:
			return "Invalid DOS signature";
		case error_codes::invalid_pe_signature:
			return "Invalid PE signature";
		case error_codes::invalid_image_type:
			return "Invalid image type";
		case error_codes::invalid_cli_header:
			return "Invalid CLI header";
		case error_codes::invalid_metadata_directory:
			return "Invalid metadata directory";
		case error_codes::invalid_stream_header:
			return "Invalid stream header";
		case error_codes::heap_out_of_bounds:
			return "Index points outside of heap";
		case error_codes::decoded_index_invalid_table:
			return "Decoded index returned invalid table ID";
		case error_codes::invalid_method_header:
			return "Method header has invalid type";
		case error_codes::invalid_method_rva:
			return "Method RVA is invalid";
		case error_codes::metadata_stream_missing:
			return "Metadata (~) stream missing";
		default:
			return NULL;
	}
}
