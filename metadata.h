#pragma once

#include <cstdint>
#include "error.h"
#include "analysis-result.h"

// Metadata table definitions.
#define METADATA_TABLE_MODULE			0
#define METADATA_TABLE_TYPE_REF			1
#define METADATA_TABLE_TYPE_DEF			2
#define METADATA_TABLE_FIELD			4
#define METADATA_TABLE_METHOD_DEF		6
#define METADATA_TABLE_PARAM			8
#define METADATA_TABLE_INTERFACE_IMPL		9
#define METADATA_TABLE_MEMBER_REF		10
#define METADATA_TABLE_CONSTANT			11
#define METADATA_TABLE_CUSTOM_ATTR		12
#define METADATA_TABLE_FIELD_MARSHAL		13
#define METADATA_TABLE_DECL_SECURITY		14
#define METADATA_TABLE_CLASS_LAYOUT		15
#define METADATA_TABLE_FIELD_LAYOUT		16
#define METADATA_TABLE_STANDALONE_SIG		17
#define METADATA_TABLE_EVENT_MAP		18
#define METADATA_TABLE_EVENT			20
#define METADATA_TABLE_PROPERTY_MAP		21
#define METADATA_TABLE_PROPERTY			23
#define METADATA_TABLE_METHOD_SEMANTICS		24
#define METADATA_TABLE_METHOD_IMPL		25
#define METADATA_TABLE_MODULE_REF		26
#define METADATA_TABLE_TYPE_SPEC		27
#define METADATA_TABLE_IMPL_MAP			28
#define METADATA_TABLE_FIELD_RVA		29
#define METADATA_TABLE_ASSEMBLY			32
#define METADATA_TABLE_ASSEMBLY_PROCESSOR	33
#define METADATA_TABLE_ASSEMBLY_OS		34
#define METADATA_TABLE_ASSEMBLY_REF		35
#define METADATA_TABLE_ASSEMBLY_OS_REF		37
#define METADATA_TABLE_FILE			38
#define METADATA_TABLE_ASSEMBLY_REF_PROCESSOR	36
#define METADATA_TABLE_EXPORTED_TYPE		39
#define METADATA_TABLE_MANIFEST_RESOURCE	40
#define METADATA_TABLE_NESTED_CLASS		41
#define METADATA_TABLE_GENERIC_PARAM		42
#define METADATA_TABLE_METHOD_SPEC		43
#define METADATA_TABLE_GENERIC_PARAM_CONSTRAINT	44

// Returns a friendly name for each metadata table, instead of just the index.
const char* get_metadata_table_name(const uint32_t idx);

// Metadata parser class.
class metadata_parser
{
private:
	// Base parameters for parsing.
	const uint8_t* tilde_stream;
	uint32_t stream_length;
	error_codes last_error_code;

	// Index sizes for other heaps throughout the program.
	uint32_t string_index_size;
	uint32_t guid_index_size;
	uint32_t blob_index_size;

	// Stream type enum,
	enum class stream_type
	{
		string,
		blob,
		guid
	};

	// Index retrieval function.
	uint32_t resolve_stream_index(const uint8_t* index_ptr, const stream_type type, uint32_t* const num_bytes) const;

	// Index resolution functions.
	uint32_t get_type_def_or_ref_index(const uint32_t index, uint32_t* const value) const;
	uint32_t get_has_constant_index(const uint32_t index, uint32_t* const value) const;
	uint32_t get_has_custom_attribute_index(const uint32_t index, uint32_t* const value) const;
	uint32_t get_has_field_marshall_index(const uint32_t index, uint32_t* const value) const;
	uint32_t get_has_decl_security_index(const uint32_t index, uint32_t* const value) const;
	uint32_t get_member_ref_parent_index(const uint32_t index, uint32_t* const value) const;
	uint32_t get_has_semantics_index(const uint32_t index, uint32_t* const value) const;
	uint32_t get_method_def_or_ref_index(const uint32_t index, uint32_t* const value) const;
	uint32_t get_member_forwarded_index(const uint32_t index, uint32_t* const value) const;
	uint32_t get_implementation_index(const uint32_t index, uint32_t* const value) const;
	uint32_t get_custom_attribute_type_index(const uint32_t index, uint32_t* const value) const;
	uint32_t get_resolution_scope_index(const uint32_t index, uint32_t* const value) const;
	uint32_t get_resolution_scope_index_size(analysis_result* const result) const;
	uint32_t get_param_index_size(analysis_result* const result) const;
	uint32_t get_type_def_or_ref_index_size(analysis_result* const result) const;
	uint32_t get_field_index_size(analysis_result* const result) const;
	uint32_t get_methoddef_index_size(analysis_result* const result) const;

	// Parses a specific metadata table by index.
	bool parse_table(const uint32_t index, const uint32_t num_rows, const uint8_t* table_offset, const int32_t remaining, uint32_t* const bytes_processed, analysis_result* const result);
public:
	metadata_parser(const uint8_t* stream_ptr, const uint32_t stream_length);
	~metadata_parser();

	error_codes get_last_error() const;

	bool parse(analysis_result* const result);
};