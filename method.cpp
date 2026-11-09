#include "method.h"

// Parses method header amd body.
const error_codes parse_method_header_body(analysis_result* result, const uint32_t rva, method& out_method)
{
	// Get pointer to method header an perform sanity check.
	const uint32_t method_file_offset = rva_to_file_offset(result, rva);
	if (!method_file_offset)
	{
		return error_codes::invalid_method_rva;
	}
	const uint8_t* method_ptr = result->image_ptr + method_file_offset;

	// Get header type byte.
	const uint8_t header_first = *method_ptr;
	const uint8_t header_type = header_first & 0x3;
	uint32_t header_size;
	if (header_type < 2) return error_codes::invalid_method_header;
	else if (header_type == 2)
	{
		// Header is in Tiny format. Get the size of the method.
		out_method.length = (header_first & 0xFC) >> 2;
		header_size = sizeof(uint8_t);
	}
	else
	{
		// Header is in Fat format. Get the method flags and compute the size of the header.
		const uint16_t first_word = *(uint16_t*)method_ptr;
		const uint16_t flags = first_word & 0xFFF0;
		header_size = (first_word >> 12) * sizeof(uint32_t);

		// Perform sanity check on reading the total Fat method header.
		if (method_ptr + header_size > result->image_ptr + result->image_size)
		{
			return error_codes::insufficient_buffer;
		}

		// Read the next fields inside the header.
		const uint16_t max_stack = *(uint16_t*)(method_ptr + sizeof(uint16_t));
		const uint32_t code_size = *(uint32_t*)(method_ptr + sizeof(uint32_t));
		out_method.max_stack = max_stack;
		out_method.length = code_size;
	}

	// Start diassembling the code.
	const uint8_t* code_ptr = method_ptr + header_size;
	const uint8_t* const code_begin = code_ptr;
	for (uint32_t rem = out_method.length; rem; )
	{
		// Get next instruction.
		instruction insn;
		const uint32_t insn_length = disasm(code_ptr, rem, insn);
		if (!insn_length) break;

		// Store instruction inside output.
		insn.offset = (uint32_t)(code_ptr - code_begin);
		out_method.disassembly.push_back(insn);

		// Update counters.
		code_ptr += insn_length;
		rem -= insn_length;
	}

	return error_codes::success;
}