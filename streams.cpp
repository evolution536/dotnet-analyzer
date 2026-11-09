#include <libreverse.h>
#include "streams.h"

// Dumps the entire #Strings stream, which contains null-terminated, ASCII strings.
bool dump_strings_stream(const analysis_result* result, std::map<uint32_t, std::string>& dumped_strings)
{
	// Check whether the Strings stream exist in the analysis result.
	if (!result->dotnet_streams.count("#Strings")) return false;

	// Get the stream buffer first.
	const std::vector<uint8_t>& stream = result->dotnet_streams.at("#Strings");
	const char* stream_ptr = (char*)&stream[0];
	const uint32_t stream_size = (uint32_t)stream.size();

	// Start dumping strings.
	uint32_t running_length = 0;
	uint32_t current_offset = 0;
	for (uint32_t i = 0; i < stream_size; ++i)
	{
		// Check for null terminator.
		if (stream_ptr[i])
		{
			// Add the next character to the current string.
			running_length++;
		}
		else
		{
			// Close the running string and store it.
			dumped_strings[current_offset] = std::string(stream_ptr + current_offset, running_length);

			// Reset the running string.
			running_length = 0;
			current_offset = i + 1;
		}
	}

	return true;
}

// Dumps the entire #US stream, which contains null-terminated, UTF-16 strings.
bool dump_unicode_strings_stream(const analysis_result* result, std::map<uint32_t, std::string>& dumped_strings)
{
	// Check whether the Strings stream exist in the analysis result.
	if (!result->dotnet_streams.count("#US")) return false;

	// Get the stream buffer first.
	const std::vector<uint8_t>& stream = result->dotnet_streams.at("#US");
	const char* stream_ptr = (char*)&stream[0];
	const uint32_t stream_size = (uint32_t)stream.size();

	// The first byte of the stream must be a null.
	if (!stream_size || stream_ptr[0] != 0) return false;

	// Read strings from the stream buffer. The first byte is a null, so we ignore that.
	uint32_t current_offset = 0;
	for (uint32_t i = 1; i < stream_size; )
	{
		// Update the current offset.
		current_offset = i;

		// Get the next compressed integer. It gives the length of the string in bytes, not characters.
		uint32_t string_length = 0;
		const uint32_t compressed_int_length = decompress_dotnet_unsigned_integer((uint8_t*)stream_ptr + i, &string_length);

		// Once the integer length becomes zero, we end up in an infinite loop and we need to quit.
		if (!compressed_int_length) break;

		// Increment the pointer with the length of the compressed integer.
		i += compressed_int_length;

		// Do we still have enough memory to read?
		if (stream_size - i < string_length) break;

		// Read the string.
		dumped_strings[current_offset] = std::string(stream_ptr + i, string_length);
		i += string_length;
	}

	return true;
}

// Dumps the entire #Blob stream containing signatures and more.
bool dump_blob_stream(const analysis_result* result, std::map<uint32_t, std::string>& dumped_blobs)
{
	// Check whether the Blob stream exist in the analysis result.
	if (!result->dotnet_streams.count("#Blob")) return false;

	// Get the stream buffer first.
	const std::vector<uint8_t>& stream = result->dotnet_streams.at("#Blob");
	const char* stream_ptr = (char*)&stream[0];
	const uint32_t stream_size = (uint32_t)stream.size();

	// The first byte of the stream must be a null.
	if (!stream_size || stream_ptr[0] != 0) return false;

	// Read strings from the stream buffer. The first byte is a null, so we ignore that.
	uint32_t current_offset = 0;
	for (uint32_t i = 1; i < stream_size; )
	{
		// Update the current offset.
		current_offset = i;

		// Get the next compressed integer. It gives the length of the string in bytes, not characters.
		uint32_t blob_length = 0;
		const uint32_t compressed_int_length = decompress_dotnet_unsigned_integer((uint8_t*)stream_ptr + i, &blob_length);

		// Once the integer length becomes zero, we end up in an infinite loop and we need to quit.
		if (!compressed_int_length) break;

		// Increment the pointer with the length of the compressed integer.
		i += compressed_int_length;

		// Do we still have enough memory to read?
		if (stream_size - i < blob_length) break;

		// Read the string.
		dumped_blobs[current_offset] = std::string(stream_ptr + i, blob_length);
		i += blob_length;
	}

	return true;
}
