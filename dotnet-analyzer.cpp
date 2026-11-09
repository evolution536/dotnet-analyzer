#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <iomanip>
#include <libreverse.h>
#include <nlohmann/json.hpp>
#include "dotnet-analyzer.h"
#include "pe.h"
#include "metadata.h"
#include "streams.h"

#ifdef _WIN32
#pragma comment(lib, "libreverse.lib")
#endif

// ------------------------------------------------------------------------
// Utility functions.
// ------------------------------------------------------------------------

// Gets poor-mans version of Unicode string, just by removing all null bytes.
static std::string get_poor_mans_utf16_string(const uint8_t* ptr, const uint32_t length)
{
	std::string out;
	for (uint32_t i = 0; i < length; i += 2)
	{
		out += ((char*)ptr)[i];
	}
	return out;
}

uint32_t rva_to_file_offset(analysis_result* const result, const uint32_t rva)
{
	// Iterate through sections and save them for application use.
	PIMAGE_SECTION_HEADER32 sec_header = (PIMAGE_SECTION_HEADER32)result->first_section_ptr;
	for (unsigned int i = 0; i < result->number_of_sections; ++i, ++sec_header)
	{
		// Check if the RVA points inside this section. If so, we need to compute the file offset inside it.
		if (rva >= sec_header->VirtualAddress && rva < (sec_header->VirtualAddress + sec_header->SizeOfRawData))
		{
			return rva - sec_header->VirtualAddress + sec_header->PointerToRawData;
		}
	}

	return 0;
}

// ------------------------------------------------------------------------
// Initial .NET file analyzer wrapper.
// ------------------------------------------------------------------------

dotnet_analyzer::dotnet_analyzer(const uint8_t* buffer, const uint32_t len)
{
	// Initialize all local variables.
	this->buffer = buffer;
	this->buffer_len = len;
	this->last_error_code = error_codes::success;
	this->result = NULL;
}

dotnet_analyzer::~dotnet_analyzer()
{
	// If the analysis result was created, we must free it.
	if (this->result)
	{
		delete this->result;
	}
}

error_codes dotnet_analyzer::get_last_error() const
{
	return this->last_error_code;
}

analysis_result* dotnet_analyzer::get_analysis_result() const
{
	return this->result;
}

bool dotnet_analyzer::run()
{
	// Check if we have enough buffer to perform initial checks. We just check the general size of headers.
	if (this->buffer_len < 0x400)
	{
		this->last_error_code = error_codes::insufficient_buffer;
		return false;
	}

	// Check the DOS header first.
	PIMAGE_DOS_HEADER32 dos_header = (PIMAGE_DOS_HEADER32)this->buffer;
	if (this->buffer_len < sizeof(uint16_t) || dos_header->e_magic != 0x5A4D)
	{
		this->last_error_code = error_codes::invalid_dos_signature;
		return false;
	}

	// Check the PE signature too.
	const uint32_t pe_signature = *(uint32_t*)(this->buffer + dos_header->e_lfanew);
	if (pe_signature != 0x4550)
	{
		this->last_error_code = error_codes::invalid_pe_signature;
		return false;
	}

	// We are about to store the first analysis results, so we will initializ the object hre.
	this->result = new analysis_result();
	this->result->image_ptr = this->buffer;
	this->result->image_size = this->buffer_len;

	// Check whether the binary is x86 or x64. Any other binary types we will ignore.
	PIMAGE_NT_HEADERS32 pe_header_tmp = (PIMAGE_NT_HEADERS32)(this->buffer + dos_header->e_lfanew);
	IMAGE_DATA_DIRECTORY32 cor20_header;
	if (pe_header_tmp->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
	{
		// Parse the headers as x86.
		PIMAGE_NT_HEADERS32 pe_header = pe_header_tmp;
		cor20_header = pe_header->OptionalHeader.DataDirectory[14];
		this->result->is_x64 = false;
		this->result->nt_headers_ptr = (uint8_t*)pe_header;
		this->result->number_of_sections = pe_header->FileHeader.NumberOfSections;
		this->result->first_section_ptr = (uint8_t*)&pe_header->OptionalHeader + pe_header->FileHeader.SizeOfOptionalHeader;
	}
	else if (pe_header_tmp->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		// Parse the headers as x64.
		PIMAGE_NT_HEADERS64 pe_header = (PIMAGE_NT_HEADERS64)(this->buffer + dos_header->e_lfanew);
		cor20_header = pe_header->OptionalHeader.DataDirectory[14];
		this->result->is_x64 = true;
		this->result->nt_headers_ptr = (uint8_t*)pe_header;
		this->result->number_of_sections = pe_header->FileHeader.NumberOfSections;
		this->result->first_section_ptr = (uint8_t*)&pe_header->OptionalHeader + pe_header->FileHeader.SizeOfOptionalHeader;
	}
	else
	{
		this->last_error_code = error_codes::invalid_image_type;
		return false;
	}

	// Check whether the size of the COR20 header is correct.
	const uint32_t cor20_size = cor20_header.Size;
	if (cor20_size != 0x48)
	{
		this->last_error_code = error_codes::invalid_cli_header;
		return false;
	}

	// We obtained the data directory to the COR20 header. Check whether it is there first.
	const uint32_t cor20_rva = rva_to_file_offset(this->result, cor20_header.VirtualAddress);
	if (!cor20_rva || !cor20_size)
	{
		this->last_error_code = error_codes::invalid_cli_header;
		return false;
	}

	// Check whether the directory points somewhere inside the buffer before reading.
	if (cor20_rva > this->buffer_len || cor20_size > this->buffer_len || cor20_rva + cor20_size > this->buffer_len)
	{
		this->last_error_code = error_codes::invalid_cli_header;
		return false;
	}

	// Move to the COR20 header and get the metadata directory.
	IMAGE_COR20_HEADER32* cor20 = (IMAGE_COR20_HEADER32*)(this->buffer + cor20_rva);
	const uint32_t metadata_rva = rva_to_file_offset(this->result, cor20->MetaData.VirtualAddress);
	const uint32_t metadata_size = cor20->MetaData.Size;

	// Store general properties about the .NET binary.
	this->result->general_properties.major_runtime_version = cor20->MajorRuntimeVersion;
	this->result->general_properties.minor_runtime_version = cor20->MinorRuntimeVersion;
	this->result->general_properties.entrypoint_token = cor20->EntryPointToken;

	// Check whether the metadata directory points inside the buffer.
	if (metadata_rva > this->buffer_len || metadata_size > this->buffer_len || metadata_rva + metadata_size > this->buffer_len)
	{
		this->last_error_code = error_codes::invalid_metadata_directory;
		return false;
	}

	// Still here, so test the signature of the .NET metadata section.
	const uint8_t* metadata_ptr = (uint8_t*)(this->buffer + metadata_rva);
	this->result->metadata_header_ptr = metadata_ptr;
	if (*(uint32_t*)metadata_ptr != 0x424A5342)
	{
		this->last_error_code = error_codes::invalid_metadata_directory;
		return false;
	}

	// Store metadata version numbers.
	this->result->general_properties.metadata_major_version = *(uint16_t*)(metadata_ptr + sizeof(uint32_t));
	this->result->general_properties.metadata_minor_version = *(uint16_t*)(metadata_ptr + sizeof(uint32_t) + sizeof(uint16_t));

	// Advance the file pointer until we reach the metadata section.
	const uint8_t* length_ptr = (metadata_ptr + 3 * sizeof(uint32_t));
	const uint32_t version_length = *(uint32_t*)length_ptr;
	metadata_ptr = length_ptr + version_length + sizeof(uint32_t) + sizeof(uint16_t);

	// We added a value from a dereferenced pointer. Perform a sanity check.
	if (metadata_ptr > this->buffer + this->buffer_len)
	{
		this->last_error_code = error_codes::invalid_metadata_directory;
		return false;
	}

	// Still here, so read the stream information.
	const uint16_t number_of_streams = *(uint16_t*)metadata_ptr;
	metadata_ptr += sizeof(uint16_t);
	uint32_t stream_iter = 0;
	while (stream_iter < number_of_streams)
	{
		// Get offset and size. The offset must be added to the file offset of the metadata header to obtain the stream pointer.
		const uint8_t* stream_ptr = this->result->metadata_header_ptr + *(uint32_t*)metadata_ptr;
		metadata_ptr += sizeof(uint32_t);
		const uint32_t stream_size = *(uint32_t*)metadata_ptr;
		metadata_ptr += sizeof(uint32_t);

		// Perform a sanity check on what we just read.
		if (stream_ptr > this->buffer + this->buffer_len || stream_ptr + stream_size > this->buffer + this->buffer_len)
		{
			this->last_error_code = error_codes::invalid_stream_header;
			return false;
		}

		// Still here. Get the name of the stream.
		uint16_t name_length = 0;
		uint16_t num_dwords_passed = 0;
		for (uint32_t* dword_iter = (uint32_t*)metadata_ptr; ; dword_iter++)
		{
			// Check if there is a zero byte anywhere in this DWORD.
			const uint32_t current_dword = *dword_iter;
			num_dwords_passed++;
			if (!current_dword) { break; }
			if (!(current_dword & 0xFF00)) { name_length += 1; break; }
			if (!(current_dword & 0xFF0000)) { name_length += 2; break; }
			if (!(current_dword & 0xFF000000)) { name_length += 3; break; }
			else { name_length += sizeof(uint32_t); }
		}

		// Perform sanity check on the name length.
		if ((uint32_t)(metadata_ptr - this->buffer) + name_length > this->buffer_len)
		{
			this->last_error_code = error_codes::invalid_stream_header;
			return false;
		}

		// Extract the name.
		std::string stream_name((char*)metadata_ptr, name_length);
		this->result->dotnet_streams[stream_name] = std::vector<uint8_t>(stream_ptr, stream_ptr + stream_size);

		// Increment the pointer to the next header.
		metadata_ptr += num_dwords_passed * sizeof(uint32_t);
		stream_iter++;
	}

	return true;
}

// ------------------------------------------------------------------------
// Main procedures.
// ------------------------------------------------------------------------

static bool parse_command_line_arguments(int argc, char** argv, std::map<std::string, std::string>& arguments)
{
	for (int i = 1; i < argc; )
	{
		std::string cur = argv[i++];
		if (cur.compare("-h") == 0 || cur.compare("--help") == 0)
		{
			arguments["help"] = "true";
		}
		else if (cur.compare("-v") == 0 || cur.compare("--verbose") == 0)
		{
			arguments["verbose"] = "true";
		}
		else if (cur.compare("-d") == 0 || cur.compare("--dump-streams") == 0)
		{
			arguments["dump_streams"] = "true";
		}
		else if (cur.compare("-m") == 0 || cur.compare("--metadata-tokens") == 0)
		{
			arguments["dump_metadata_tokens"] = "true";
		}
		else if (cur.compare("-u") == 0 || cur.compare("--format-unicode") == 0)
		{
			arguments["format_unicode"] = "true";
		}
		else if ((cur.compare("-f") == 0 || cur.compare("--input-file") == 0) && i < argc)
		{
			arguments["input_file"] = std::string(argv[i++]);
		}
		else
		{
			std::cout << "ERROR: Invalid argument encountered: " << cur << std::endl;
			return false;
		}
	}

	return true;
}

static void print_help()
{
	std::cout << "dotnet-analyzer for reversing .NET binaries." << std::endl;
	std::cout << "Usage: dotnet-analyzer -f <input_file [options]" << std::endl << std::endl;
	std::cout << "Basic parameters:" << std::endl;
	std::cout << "-h,--help\t\tRequests this help menu." << std::endl;
	std::cout << "-v,--verbose\t\tEnables verbose output." << std::endl;
	std::cout << "-f,--input-file\t\tSpecifies the input binary file." << std::endl;
	std::cout << std::endl << "Output parameters:" << std::endl;
	std::cout << "-d,--dump-streams\tDumps the contents of detected .NET streams." << std::endl;
	std::cout << "-m,--metadata-tokens\tDumps machine-readable list of metadata tokens in the tables." << std::endl;
}

int main(int argc, char** argv)
{
	// Parse command line arguments.
	std::map<std::string, std::string> args;
	if (!parse_command_line_arguments(argc, argv, args))
	{
		std::cout << "ERROR: Parsing command line arguments failed!" << std::endl;
		return 1;
	}

	// Check whether the help menu is requested.
	if (args.count("help"))
	{
		print_help();
		return 0;
	}

	// Check whether verbose mode is requested.
	const bool verbose = !!args.count("verbose");

	// Check whether the contents of detected streams should be dumped.
	const bool dump_streams = !!args.count("dump_streams");

	// Check whether Unicode strings should be formatted as readable, the poor-mans way.
	const bool format_unicode = !!args.count("format_unicode");

	// Check whether the dumping of referenced metadata tokens is requested.
	const bool dump_metadata_tokens = !!args.count("dump_metadata_tokens");

	// Some operations are mutually exclusive.
	if (dump_streams && dump_metadata_tokens)
	{
		std::cout << "ERROR: The -d and -m switches are mutually exclusive!" << std::endl;
		return 1;
	}

	// Check whether the input file has been specified.
	if (!args.count("input_file"))
	{
		std::cout << "ERROR: Please specify the input file using the -f switch!" << std::endl;
		return 1;
	}

	// Open the input file for reading.
	std::ifstream input_file(args["input_file"], std::ios::binary);

	// Test whether the file is open for reading.
	if (!input_file.is_open())
	{
		std::cout << "ERROR: Failed to open the input file!" << std::endl;
		return 1;
	}

	// Read file into buffer locally. We just one buffer so we manage it from here.
	std::vector<uint8_t> buffer(std::istreambuf_iterator<char>(input_file), {});

	// Start .NET analysis.
	dotnet_analyzer analyzer(&buffer[0], (uint32_t)buffer.size());
	const bool result = analyzer.run();
	if (result)
	{
		// Retrieve the analysis result.
		analysis_result* const result = analyzer.get_analysis_result();
		if (!result)
		{
			std::cout << "ERROR: Analysis result is NULL!" << std::endl;
			return 1;
		}

		// Print general properties of the binary in verbose mode.
		if (verbose)
		{
			std::cout << "INFO: Runtime version: " << std::to_string(result->general_properties.major_runtime_version) + "." + std::to_string(result->general_properties.minor_runtime_version) << std::endl;
			std::cout << "INFO: Metadata version: " << std::to_string(result->general_properties.metadata_major_version) + "." + std::to_string(result->general_properties.metadata_minor_version) << std::endl;
			for (auto const& stream : result->dotnet_streams)
			{
				std::cout << "INFO: Found .NET stream: " << stream.first << ", size: " << stream.second.size() << std::endl;
			}
		}

		// Test whether we have the '~' stream. This will be used to parse metadata from.
		if (!result->dotnet_streams.count("#~"))
		{
			std::cout << "ERROR: No metadata stream (#~) was detected in the binary!" << std::endl;
			return 1;
		}

		// Start parsing the .NET metadata.
		const std::vector<uint8_t>& tilde_stream = result->dotnet_streams["#~"];
		metadata_parser parser(&tilde_stream[0], (uint32_t)tilde_stream.size());
		if (!parser.parse(result))
		{
			// Get last error code and print friendly message.
			auto err = parser.get_last_error();
			std::cout << "ERROR: Last error code: " << (int)err << " (" << get_error_code_message(err) << ")" << std::endl;
			return 1;
		}

		// Display metadata results in verbose mode.
		if (verbose)
		{
			for (auto const& table : result->metadata_tables)
			{
				const char* table_name = get_metadata_table_name(table.first);
				std::cout << "INFO: Detected metadata table: " << table.first << " (" << (table_name ? table_name : "") << ") having " << table.second << " rows." << std::endl;
			}
		}

		// Do the contents of detected streams have to dumped?
		if (dump_streams)
		{
			// Dump the #Strings stream first.
			std::map<uint32_t, std::string> dumped_strings;
			if (!dump_strings_stream(result, dumped_strings))
			{
				std::cout << "WARNING: #Strings stream was not detected!" << std::endl;
			}

			// Print the strings.
			for (auto const& str : dumped_strings)
			{
				std::cout << "INFO: #Strings offset: " << str.first << " --> " << string_escape_unreadable(str.second) << std::endl;
			}

			// Dump the #US stream next.
			std::map<uint32_t, std::string> dumped_unicode_strings;
			if (!dump_unicode_strings_stream(result, dumped_unicode_strings))
			{
				std::cout << "WARNING: #US stream was not detected or contains invalid data!" << std::endl;
			}

			// Print the strings.
			for (auto const& str : dumped_unicode_strings)
			{
				if (format_unicode)
				{

					std::cout << "INFO: #US offset: " << str.first << " --> " << get_poor_mans_utf16_string((uint8_t*)str.second.c_str(), (uint32_t)str.second.size()) << std::endl;
				}
				else
				{
					std::cout << "INFO: #US offset: " << str.first << " --> " << string_escape_unreadable(str.second) << std::endl;
				}
			}

			// Dump the #Blob stream as well.
			std::map<uint32_t, std::string> dumped_blobs;
			if (!dump_blob_stream(result, dumped_blobs))
			{
				std::cout << "WARNING: #Blob stream was not detected or contains invalid data!" << std::endl;
			}

			// Print the blobs.
			for (auto const& blob : dumped_blobs)
			{
				std::cout << "INFO: #Blob offset: " << blob.first << " --> " << string_escape_unreadable(blob.second) << std::endl;
			}
		}
		else if (dump_metadata_tokens)
		{
			// Output CSV header with relevant information.
			std::cout << "token,name,type" << std::endl;

			// Dump the tokens for relevant metadata information parsed from the binary.
			for (uint32_t i = 0; i < result->typerefs.size(); ++i)
			{
				const uint32_t token = (METADATA_TABLE_TYPE_REF << 24) | (i + 1);
				std::string full_name;
				if (!result->typerefs[i].namespace_name.empty())
				{
					full_name = result->typerefs[i].namespace_name + ".";
				}
				full_name += result->typerefs[i].type_name;
				std::cout << "0x" << std::setfill('0') << std::setw(8) << std::hex << token << std::dec << "," << full_name << ",TypeRef" << std::endl;
			}

			for (uint32_t i = 0; i < result->typedefs.size(); ++i)
			{
				const uint32_t token = (METADATA_TABLE_TYPE_DEF << 24) | (i + 1);
				std::string full_name;
				if (!result->typedefs[i].namespace_name.empty())
				{
					full_name = result->typedefs[i].namespace_name + ".";
				}
				full_name += result->typedefs[i].type_name;
				std::cout << "0x" << std::setfill('0') << std::setw(8) << std::hex << token << std::dec << "," << full_name << ",TypeDef" << std::endl;
			}

			for (uint32_t i = 0; i < result->methods.size(); ++i)
			{
				const uint32_t token = (METADATA_TABLE_METHOD_DEF << 24) | (i + 1);
				std::cout << "0x" << std::setfill('0') << std::setw(8) << std::hex << token << std::dec << "," << result->methods[i].name << ",Method" << std::endl;
			}
		}

		// Dump metadata structure in verbose mode.
		if (verbose)
		{
			// The module information first.
			std::cout << "INFO: ----------------------------------------------------" << std::endl;
			std::cout << "INFO: Module name: " << string_escape_unreadable(result->module.name) << std::endl;

			// Print defined type names.
			std::cout << "INFO: ----------------------------------------------------" << std::endl;
			for (const type_def& ref : result->typedefs)
			{
				std::cout << "INFO: Found defined type: " << string_escape_unreadable(ref.to_string()) << std::endl;
			}

			// Print referenced type names.
			std::cout << "INFO: ----------------------------------------------------" << std::endl;
			for (const typeref& ref : result->typerefs)
			{
				std::cout << "INFO: Found referenced type: " << string_escape_unreadable(ref.to_string()) << std::endl;
			}

			std::cout << "INFO: ----------------------------------------------------" << std::endl;
			for (const method& m : result->methods)
			{
				std::cout << "INFO: Found method: " << string_escape_unreadable(m.to_string()) << std::endl;
				if (m.disassembly.empty()) continue;
				std::cout << "Disassembly:" << std::endl;
				for (auto& insn : m.disassembly)
				{
					std::cout << insn.to_string() << std::endl;
				}
			}
		}
	}
	else
	{
		// Get last error code and print friendly message.
		auto err = analyzer.get_last_error();
		std::cout << "ERROR: Analysis failed! Last error code: " << (int)err << " (" << get_error_code_message(err) << ")" << std::endl;
	}

	return 0;
}
