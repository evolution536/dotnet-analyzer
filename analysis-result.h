#pragma once

#include <string>
#include <cstdint>
#include <vector>
#include <map>
#include "disasm.h"

// Represents a TypeDef object.
struct type_def
{
	// Name of the type.
	std::string type_name;

	// Name of the namespace.
	std::string namespace_name;

	// Initializing constructor.
	type_def(const char* type_name_ptr, const char* type_namespace_ptr)
	{
		this->type_name = std::string(type_name_ptr);
		this->namespace_name = std::string(type_namespace_ptr);
	};

	// Easy conversion from struct to string.
	std::string to_string() const
	{
		return this->namespace_name + "." + this->type_name;
	};
};

// Defines a TypeRef object in the analysis result.
struct typeref
{
	// Name of the type.
	std::string type_name;

	// Name of the namespace.
	std::string namespace_name;

	// Initializing constructor.
	typeref(const char* type_name_ptr, const char* type_namespace_ptr)
	{
		this->type_name = std::string(type_name_ptr);
		this->namespace_name = std::string(type_namespace_ptr);
	};

	// Easy conversion from struct to string.
	std::string to_string() const
	{
		return this->namespace_name + "." + this->type_name;
	};
};

// Represents a method in the analysis result.
struct method
{
	// RVA to the method header and body.
	uint32_t rva;

	// Name of the method as taken from metadata.
	std::string name;

	// Stores the length of the method body in bytes.
	uint32_t length;

	// Maximum number of elements on the operand stack.
	uint32_t max_stack;

	// List of disassembled instructions.
	std::vector<instruction> disassembly;

	// Initializing constructor.
	method(const uint32_t rva, const char* method_name)
	{
		this->rva = rva;
		this->name = method_name;
		this->max_stack = 0;
		this->length = 0;
	}

	// Easy conversion from struct to string for convenience.
	std::string to_string() const
	{
		return this->name + " (Size: " + std::to_string(this->length) + ")"; // FIXME: include parameters!
	};
};

// Represents an analysis result, containing all fields and properties extracted from the input binary.
struct analysis_result
{
	// Fundamental properties of the input file, used to compute RVAs and such.
	const uint8_t* image_ptr;
	uint32_t image_size;

	// Properties about the image, needed to compute file offsets from RVAs for example.
	bool is_x64;
	const uint8_t* nt_headers_ptr;
	uint32_t number_of_sections;
	const uint8_t* first_section_ptr;
	const uint8_t* metadata_header_ptr;

	// Generic .NET properties.
	struct
	{
		uint16_t major_runtime_version;
		uint16_t minor_runtime_version;
		uint16_t metadata_major_version;
		uint16_t metadata_minor_version;

		// The metadata token of the method where the entrypoint of the program is.
		uint32_t entrypoint_token;
	} general_properties;

	// Dictionary of streams in the metadata section.
	std::map<std::string, std::vector<uint8_t>> dotnet_streams;

	// Dictionary of metadata streams present in the binary file.
	std::map<uint32_t, uint32_t> metadata_tables;

	// Module information from metadata.
	struct
	{
		// The name of the module.
		std::string name;
	} module;

	// Store TypeRefs from the metadata.
	std::vector<typeref> typerefs;

	// Store TypeDefs from the metadata.
	std::vector<type_def> typedefs;

	// Store MethodDef entries from the metadata.
	std::vector<method> methods;
};

// Utility function that converts an RVA to an actual file offset.
uint32_t rva_to_file_offset(analysis_result* const result, const uint32_t rva);