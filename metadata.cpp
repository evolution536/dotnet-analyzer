#include "metadata.h"
#include "dotnet.h"
#include "method.h"

// Returns a friendly name for each metadata table, instead of just the index.
const char* get_metadata_table_name(const uint32_t idx)
{
	switch (idx)
	{
		case METADATA_TABLE_MODULE: return "Module";
		case METADATA_TABLE_TYPE_REF: return "TypeRef";
		case METADATA_TABLE_TYPE_DEF: return "TypeDef";
		case METADATA_TABLE_FIELD: return "Field";
		case METADATA_TABLE_METHOD_DEF: return "MethodDef";
		case METADATA_TABLE_PARAM: return "Param";
		case METADATA_TABLE_INTERFACE_IMPL: return "InterfaceImpl";
		case METADATA_TABLE_MEMBER_REF: return "MemberRef";
		case METADATA_TABLE_CONSTANT: return "Constant";
		case METADATA_TABLE_CUSTOM_ATTR: return "CustomAttr";
		case METADATA_TABLE_FIELD_MARSHAL: return "FieldMarshal";
		case METADATA_TABLE_DECL_SECURITY: return "DeclSecurity";
		case METADATA_TABLE_CLASS_LAYOUT: return "ClassLayout";
		case METADATA_TABLE_FIELD_LAYOUT: return "FieldLayout";
		case METADATA_TABLE_STANDALONE_SIG: return "StandaloneSig";
		case METADATA_TABLE_EVENT_MAP: return "EventMap";
		case METADATA_TABLE_EVENT: return "Event";
		case METADATA_TABLE_PROPERTY_MAP: return "PropertyMap";
		case METADATA_TABLE_PROPERTY: return "Property";
		case METADATA_TABLE_METHOD_SEMANTICS: return "MethodSemantics";
		case METADATA_TABLE_METHOD_IMPL: return "MethodImpl";
		case METADATA_TABLE_MODULE_REF: return "ModuleRef";
		case METADATA_TABLE_TYPE_SPEC: return "TypeSpec";
		case METADATA_TABLE_IMPL_MAP: return "ImplMap";
		case METADATA_TABLE_FIELD_RVA: return "FieldRVA";
		case METADATA_TABLE_ASSEMBLY: return "Assembly";
		case METADATA_TABLE_ASSEMBLY_PROCESSOR: return "AssemblyProcessor";
		case METADATA_TABLE_ASSEMBLY_OS: return "AssemblyOS";
		case METADATA_TABLE_ASSEMBLY_REF: return "AssemblyRef";
		case METADATA_TABLE_ASSEMBLY_OS_REF: return "AssemblyOSRef";
		case METADATA_TABLE_FILE: return "File";
		case METADATA_TABLE_ASSEMBLY_REF_PROCESSOR: return "AssemblyRefProcessor";
		case METADATA_TABLE_EXPORTED_TYPE: return "ExportedType";
		case METADATA_TABLE_MANIFEST_RESOURCE: return "ManifestResource";
		case METADATA_TABLE_NESTED_CLASS: return "NestedClass";
		case METADATA_TABLE_GENERIC_PARAM: return "GenericParam";
		case METADATA_TABLE_METHOD_SPEC: return "MethodSpec";
		case METADATA_TABLE_GENERIC_PARAM_CONSTRAINT: return "GenericParamConstraint";
		default: return NULL;
	}
}

// ---------------------------------------------------------------------------

metadata_parser::metadata_parser(const uint8_t* stream_ptr, const uint32_t stream_length)
{
	this->tilde_stream = stream_ptr;
	this->stream_length = stream_length;
	this->last_error_code = error_codes::success;
	this->string_index_size = 0;
	this->guid_index_size = 0;
	this->blob_index_size = 0;
}

metadata_parser::~metadata_parser()
{

}

// Resolves TypeDefOrRef index.
uint32_t metadata_parser::get_type_def_or_ref_index(const uint32_t index, uint32_t* const value) const
{
	const uint8_t table = index & 3;
	*value = (index & ~3) >> 2;
	switch (table)
	{
		case 0: return METADATA_TABLE_TYPE_DEF;
		case 1: return METADATA_TABLE_TYPE_REF;
		case 2: return METADATA_TABLE_TYPE_SPEC;
		default: return 0xFFFFFFFF;
	}
}

uint32_t metadata_parser::get_has_constant_index(const uint32_t index, uint32_t* const value) const
{
	const uint8_t table = index & 3;
	*value = (index & ~3) >> 2;
	switch (table)
	{
		case 0: return METADATA_TABLE_FIELD;
		case 1: return METADATA_TABLE_PARAM;
		case 2: return METADATA_TABLE_PROPERTY;
		default: return 0xFFFFFFFF;
	}
}

uint32_t metadata_parser::get_has_custom_attribute_index(const uint32_t index, uint32_t* const value) const
{
	const uint8_t table = index & 31;
	*value = (index & ~31) >> 5;
	switch (table)
	{
		case 0: return METADATA_TABLE_METHOD_DEF;
		case 1: return METADATA_TABLE_FIELD;
		case 2: return METADATA_TABLE_TYPE_REF;
		case 3: return METADATA_TABLE_TYPE_DEF;
		case 4: return METADATA_TABLE_PARAM;
		case 5: return METADATA_TABLE_INTERFACE_IMPL;
		case 6: return METADATA_TABLE_MEMBER_REF;
		case 7: return METADATA_TABLE_MODULE;
		case 8: return METADATA_TABLE_DECL_SECURITY;
		case 9: return METADATA_TABLE_PROPERTY;
		case 10: return METADATA_TABLE_EVENT;
		case 11: return METADATA_TABLE_STANDALONE_SIG;
		case 12: return METADATA_TABLE_MODULE_REF;
		case 13: return METADATA_TABLE_TYPE_SPEC;
		case 14: return METADATA_TABLE_ASSEMBLY;
		case 15: return METADATA_TABLE_ASSEMBLY_REF;
		case 16: return METADATA_TABLE_FILE;
		case 17: return METADATA_TABLE_EXPORTED_TYPE;
		case 18: return METADATA_TABLE_MANIFEST_RESOURCE;
		default: return 0xFFFFFFFF;
	}
}

uint32_t metadata_parser::get_has_field_marshall_index(const uint32_t index, uint32_t* const value) const
{
	const uint8_t table = index & 1;
	*value = (index & ~1) >> 1;
	switch (table)
	{
		case 0: return METADATA_TABLE_FIELD;
		case 1: return METADATA_TABLE_PARAM;
		default: return 0xFFFFFFFF;
	}
}

uint32_t metadata_parser::get_has_decl_security_index(const uint32_t index, uint32_t* const value) const
{
	const uint8_t table = index & 3;
	*value = (index & ~3) >> 2;
	switch (table)
	{
		case 0: return METADATA_TABLE_TYPE_DEF;
		case 1: return METADATA_TABLE_METHOD_DEF;
		case 2: return METADATA_TABLE_ASSEMBLY;
		default: return 0xFFFFFFFF;
	}
}

uint32_t metadata_parser::get_member_ref_parent_index(const uint32_t index, uint32_t* const value) const
{
	const uint8_t table = index & 7;
	*value = (index & ~7) >> 3;
	switch (table)
	{
		case 0: return METADATA_TABLE_TYPE_DEF;
		case 1: return METADATA_TABLE_TYPE_REF;
		case 2: return METADATA_TABLE_MODULE_REF;
		case 3: return METADATA_TABLE_METHOD_DEF;
		case 4: return METADATA_TABLE_TYPE_SPEC;
		default: return 0xFFFFFFFF;
	}
}

uint32_t metadata_parser::get_has_semantics_index(const uint32_t index, uint32_t* const value) const
{
	const uint8_t table = index & 1;
	*value = (index & ~1) >> 1;
	switch (table)
	{
		case 0: return METADATA_TABLE_EVENT;
		case 1: return METADATA_TABLE_PROPERTY;
		default: return 0xFFFFFFFF;
	}
}

uint32_t metadata_parser::get_method_def_or_ref_index(const uint32_t index, uint32_t* const value) const
{
	const uint8_t table = index & 1;
	*value = (index & ~1) >> 1;
	switch (table)
	{
		case 0: return METADATA_TABLE_METHOD_DEF;
		case 1: return METADATA_TABLE_MEMBER_REF;
		default: return 0xFFFFFFFF;
	}
}

uint32_t metadata_parser::get_member_forwarded_index(const uint32_t index, uint32_t* const value) const
{
	const uint8_t table = index & 1;
	*value = (index & ~1) >> 1;
	switch (table)
	{
		case 0: return METADATA_TABLE_FIELD;
		case 1: return METADATA_TABLE_METHOD_DEF;
		default: return 0xFFFFFFFF;
	}
}

uint32_t metadata_parser::get_implementation_index(const uint32_t index, uint32_t* const value) const
{
	const uint8_t table = index & 3;
	*value = (index & ~3) >> 2;
	switch (table)
	{
		case 0: return METADATA_TABLE_FILE;
		case 1: return METADATA_TABLE_ASSEMBLY_REF;
		case 2: return METADATA_TABLE_EXPORTED_TYPE;
		default: return 0xFFFFFFFF;
	}
}

uint32_t metadata_parser::get_custom_attribute_type_index(const uint32_t index, uint32_t* const value) const
{
	const uint8_t table = index & 7;
	*value = (index & ~7) >> 3;
	switch (table)
	{
		case 2: return METADATA_TABLE_METHOD_DEF;
		case 3: return METADATA_TABLE_MEMBER_REF;
		default: return 0xFFFFFFFF;
	}
}

uint32_t metadata_parser::get_resolution_scope_index(const uint32_t index, uint32_t* const value) const
{
	const uint8_t table = index & 3;
	*value = (index & ~3) >> 2;
	switch (table)
	{
		case 0: return METADATA_TABLE_MODULE;
		case 1: return METADATA_TABLE_MODULE_REF;
		case 2: return METADATA_TABLE_ASSEMBLY_REF;
		case 3: return METADATA_TABLE_TYPE_REF;
		default: return 0xFFFFFFFF;
	}
}

// Determines the size of the index in memory for a ResolutionScope index.
uint32_t metadata_parser::get_resolution_scope_index_size(analysis_result* const result) const
{
	// Get row count for the specified table and determine index size.
	const uint32_t module_row_count = result->metadata_tables[METADATA_TABLE_MODULE];
	const uint32_t module_ref_row_count = result->metadata_tables[METADATA_TABLE_MODULE_REF];
	const uint32_t assembly_ref_row_count = result->metadata_tables[METADATA_TABLE_ASSEMBLY_REF];
	const uint32_t type_ref_row_count = result->metadata_tables[METADATA_TABLE_TYPE_REF];
	if (module_row_count > 0xFFFF || module_ref_row_count > 0xFFFF || assembly_ref_row_count > 0xFFFF || type_ref_row_count > 0xFFFF)
	{
		return sizeof(uint32_t);
	}
	else return sizeof(uint16_t);
}

// Determine the size of the index in memory for an index into the Param table.
uint32_t metadata_parser::get_param_index_size(analysis_result* const result) const
{
	const uint32_t param_row_count = result->metadata_tables[METADATA_TABLE_PARAM];
	if (param_row_count > 0xFFFF)
	{
		return sizeof(uint32_t);
	}
	else return sizeof(uint16_t);
}

// Determine the size of the index in memory for a TypeDefOrRef coded index.
uint32_t metadata_parser::get_type_def_or_ref_index_size(analysis_result* const result) const
{
	const uint32_t typedef_row_count = result->metadata_tables[METADATA_TABLE_TYPE_DEF];
	const uint32_t typeref_row_count = result->metadata_tables[METADATA_TABLE_TYPE_REF];
	const uint32_t typespec_row_count = result->metadata_tables[METADATA_TABLE_TYPE_SPEC];
	if (typedef_row_count > 0xFFFF || typeref_row_count > 0xFFFF || typespec_row_count > 0xFFFF)
	{
		return sizeof(uint32_t);
	}
	else return sizeof(uint16_t);
}

uint32_t metadata_parser::get_field_index_size(analysis_result* const result) const
{
	const uint32_t field_row_count = result->metadata_tables[METADATA_TABLE_FIELD];
	if (field_row_count > 0xFFFF)
	{
		return sizeof(uint32_t);
	}
	else return sizeof(uint16_t);
}

uint32_t metadata_parser::get_methoddef_index_size(analysis_result* const result) const
{
	const uint32_t field_row_count = result->metadata_tables[METADATA_TABLE_METHOD_DEF];
	if (field_row_count > 0xFFFF)
	{
		return sizeof(uint32_t);
	}
	else return sizeof(uint16_t);
}

// Resolvees an index into one of the streams/heaps.
uint32_t metadata_parser::resolve_stream_index(const uint8_t* index_ptr, const stream_type type, uint32_t* const num_bytes) const
{
	uint32_t index_value;
	switch (type)
	{
		// When it is about an index into the strings heap.
		case stream_type::string:
			if (this->string_index_size == sizeof(uint16_t))
			{
				index_value = *(uint16_t*)index_ptr;
				*num_bytes = sizeof(uint16_t);
			}
			else
			{
				index_value = *(uint32_t*)index_ptr;
				*num_bytes = sizeof(uint32_t);
			}
			break;

		// When it is about an index into the blob heap.
		case stream_type::blob:
			if (this->blob_index_size == sizeof(uint16_t))
			{
				index_value = *(uint16_t*)index_ptr;
				*num_bytes = sizeof(uint16_t);
			}
			else
			{
				index_value = *(uint32_t*)index_ptr;
				*num_bytes = sizeof(uint32_t);
			}
			break;

		// When it is about an index into the GUID heap.
		case stream_type::guid:
			if (this->guid_index_size == sizeof(uint16_t))
			{
				index_value = *(uint16_t*)index_ptr;
				*num_bytes = sizeof(uint16_t);
			}
			else
			{
				index_value = *(uint32_t*)index_ptr;
				*num_bytes = sizeof(uint32_t);
			}
			break;

		// Unknown stream type.
		default:
			return -1;
	}

	return index_value;
}

// Parses a given metadata table by its ID and number of rows.
bool metadata_parser::parse_table(const uint32_t index, const uint32_t num_rows, const uint8_t* table_offset, const int32_t remaining, uint32_t* const bytes_processed, analysis_result* const result)
{
	// Keep track of the row size.
	const uint8_t* row_iter = table_offset;
	const uint8_t* row_iter_begin = row_iter;

	// Get references to streams for convinience.
	const std::vector<uint8_t>& strings_heap = result->dotnet_streams["#Strings"];
	const std::vector<uint8_t>& blob_heap = result->dotnet_streams["#Blob"];
	const std::vector<uint8_t>& guid_heap = result->dotnet_streams["#GUID"];

	// FIXME: must check if enough memory is there to read the table!

	// Get the ID of the table and parse it accordingly.
	if (index == METADATA_TABLE_MODULE)
	{
		// This table usually has only one row.
		if (num_rows > 0)
		{
			// Check if there is enough memory available to read this entire table.
			if (remaining < sizeof(uint16_t) + sizeof(uint32_t) * 4)
			{
				this->last_error_code = error_codes::insufficient_buffer;
				return false;
			}

			// Get the name index into the string heap. We skip the Generation field, which is reserved.
			uint32_t num_bytes_string;
			row_iter += sizeof(uint16_t);
			uint32_t name_index = this->resolve_stream_index(row_iter, stream_type::string, &num_bytes_string);
			row_iter += num_bytes_string;

			// Get the Mvid index into the GUID heap.
			uint32_t num_bytes_guid;
			uint32_t mvid_index = this->resolve_stream_index(row_iter, stream_type::guid, &num_bytes_guid);
			row_iter += (uint32_t)(3 * (uint64_t)num_bytes_guid);

			// Perform sanity checking on the indices.
			if (name_index > strings_heap.size() || mvid_index > guid_heap.size())
			{
				this->last_error_code = error_codes::heap_out_of_bounds;
				return false;
			}

			// Store the name and GUID in the analysis result.
			result->module.name = std::string((char*)&strings_heap[name_index]);

			// FIXME: GUID.
		}
	}
	else if (index == METADATA_TABLE_FIELD)
	{
		// Check if there is enough memory left to read.
		if ((uint32_t)remaining < num_rows * (sizeof(uint16_t) + 2 * sizeof(uint32_t)))
		{
			this->last_error_code = error_codes::insufficient_buffer;
			return false;
		}

		// Go on and parse the table rows.
		for (uint32_t i = 0; i < num_rows; ++i)
		{
			// Get flags.
			const uint16_t flags = *(uint16_t*)row_iter;
			row_iter += sizeof(uint16_t);

			// Get the field name.
			uint32_t num_bytes_string;
			uint32_t name_index = this->resolve_stream_index(row_iter, stream_type::string, &num_bytes_string);
			row_iter += num_bytes_string;

			// Get field signature from blob heap.
			uint32_t num_bytes_blob;
			const uint32_t signature_index = this->resolve_stream_index(row_iter, stream_type::blob, &num_bytes_blob);
			row_iter += num_bytes_blob;

			// Perform sanity checking on the indices.
			if (name_index > strings_heap.size() || signature_index > blob_heap.size())
			{
				this->last_error_code = error_codes::heap_out_of_bounds;
				return false;
			}

			// FIXME: Do stuff with fields. The reference goes from method to field, not the other way around.
		}
	}
	else if (index == METADATA_TABLE_INTERFACE_IMPL)
	{

	}
	else if (index == METADATA_TABLE_CUSTOM_ATTR)
	{

	}
	else if (index == METADATA_TABLE_CLASS_LAYOUT)
	{

	}
	else if (index == METADATA_TABLE_EVENT_MAP)
	{

	}
	else if (index == METADATA_TABLE_PROPERTY)
	{

	}
	else if (index == METADATA_TABLE_MODULE_REF)
	{

	}
	else if (index == METADATA_TABLE_FIELD_RVA)
	{

	}
	else if (index == METADATA_TABLE_ASSEMBLY_OS)
	{

	}
	else if (index == METADATA_TABLE_ASSEMBLY_OS_REF)
	{

	}
	else if (index == METADATA_TABLE_MANIFEST_RESOURCE)
	{

	}
	else if (index == METADATA_TABLE_GENERIC_PARAM_CONSTRAINT)
	{

	}
	else if (index == METADATA_TABLE_TYPE_REF)
	{
		// Test whether there is enough memory available to read.
		if ((uint32_t)remaining < num_rows * (sizeof(uint32_t) * 3))
		{
			this->last_error_code = error_codes::insufficient_buffer;
			return false;
		}

		// Go on and parse the table rows.
		for (uint32_t i = 0; i < num_rows; ++i)
		{
			// Get table ID and index for resolution scope.
			uint32_t resolution_scope_idx;
			const uint32_t table_id = this->get_resolution_scope_index(*(uint32_t*)row_iter, &resolution_scope_idx);
			row_iter += this->get_resolution_scope_index_size(result);
			if (table_id == -1)
			{
				this->last_error_code = error_codes::decoded_index_invalid_table;
				return false;
			}

			// Get type name.
			uint32_t num_bytes_string;
			uint32_t type_name_index = this->resolve_stream_index(row_iter, stream_type::string, &num_bytes_string);
			row_iter += num_bytes_string;

			// Get type namespace name.
			uint32_t type_namespace_index = this->resolve_stream_index(row_iter, stream_type::string, &num_bytes_string);
			row_iter += num_bytes_string;

			// Perform sanity checking on the indices
			if (type_name_index > strings_heap.size() || type_namespace_index > strings_heap.size())
			{
				this->last_error_code = error_codes::heap_out_of_bounds;
				return false;
			}

			// FIXME: Do something with the resolution scope.

			// Set name strings in the output.
			result->typerefs.push_back(typeref((char*)&strings_heap[type_name_index], (char*)&strings_heap[type_namespace_index]));
		}
	}
	else if (index == METADATA_TABLE_METHOD_DEF)
	{
		// Test whether there is enough memory available to read.
		const uint32_t param_list_idx_size = this->get_param_index_size(result);
		if ((uint32_t)remaining < num_rows * (sizeof(uint32_t) * 3 + param_list_idx_size + sizeof(uint16_t) * 2))
		{
			this->last_error_code = error_codes::insufficient_buffer;
			return false;
		}

		for (uint32_t i = 0; i < num_rows; ++i)
		{
			// Get RVA and flags.
			const uint32_t rva = *(uint32_t*)row_iter;
			row_iter += sizeof(uint32_t);
			const uint16_t impl_flags = *(uint16_t*)row_iter;
			row_iter += sizeof(uint16_t);
			const uint16_t flags = *(uint16_t*)row_iter;
			row_iter += sizeof(uint16_t);

			// Get method name from Strings heap.
			uint32_t num_bytes_string;
			const uint32_t method_name_index = this->resolve_stream_index(row_iter, stream_type::string, &num_bytes_string);
			row_iter += num_bytes_string;

			// Get method signature from blob heap.
			uint32_t num_bytes_blob;
			const uint32_t signature_index = this->resolve_stream_index(row_iter, stream_type::blob, &num_bytes_blob);
			row_iter += num_bytes_blob;

			// Perform sanity checking on the indices.
			if (method_name_index > strings_heap.size() || signature_index > blob_heap.size())
			{
				this->last_error_code = error_codes::heap_out_of_bounds;
				return false;
			}

			// Get index to parameters. From the documentation:
			// ------------------------------------------------
			// It marks the first of a contiguous run of Parameters owned by this method. The run continues to the smaller of:
			// - The last row of the Param table.
			// - The next run of Parameters, found by inspecting the ParamList of the next row in the MethodDef table
			uint32_t param_list_start_idx = 0;
			if (param_list_idx_size == sizeof(uint32_t))
			{
				param_list_start_idx = *(uint32_t*)row_iter;
			}
			else
			{
				param_list_start_idx = *(uint16_t*)row_iter;
			}
			row_iter += param_list_idx_size;

			// Store method object in the analysis result.
			result->methods.push_back(method(rva, (char*)&strings_heap[method_name_index]));
			method& method_obj = result->methods.back();

			// FIXME: inspect next run of ParamList to determine number of params!

			// If the RVA is zero, it might be an external method or some sort.
			if (!rva) continue;

			// Resolve RVA, parse method header and disassemble instructions.
			const error_codes last_error = parse_method_header_body(result, rva, method_obj);
			if (last_error != error_codes::success)
			{
				this->last_error_code = last_error;
				return false;
			}

			// FIXME: parse signature and flags.
		}
	}
	else if (index == METADATA_TABLE_MEMBER_REF)
	{

	}
	else if (index == METADATA_TABLE_FIELD_MARSHAL)
	{

	}
	else if (index == METADATA_TABLE_FIELD_LAYOUT)
	{

	}
	else if (index == METADATA_TABLE_EVENT)
	{

	}
	else if (index == METADATA_TABLE_METHOD_SEMANTICS)
	{

	}
	else if (index == METADATA_TABLE_TYPE_SPEC)
	{

	}
	else if (index == METADATA_TABLE_ASSEMBLY)
	{

	}
	else if (index == METADATA_TABLE_ASSEMBLY_REF)
	{

	}
	else if (index == METADATA_TABLE_FILE)
	{

	}
	else if (index == METADATA_TABLE_NESTED_CLASS)
	{

	}
	else if (index == METADATA_TABLE_TYPE_DEF)
	{
		// Test whether there is enough memory available to read.
		if ((uint32_t)remaining < num_rows * (sizeof(uint32_t) * 6))
		{
			this->last_error_code = error_codes::insufficient_buffer;
			return false;
		}

		// Process rows in the TypeDef table.
		for (uint32_t i = 0; i < num_rows; ++i)
		{
			// Get flags mask from the table row.
			const uint32_t flags = *(uint32_t*)row_iter;
			row_iter += sizeof(uint32_t);
			
			// Get type name and namespace name.
			uint32_t num_bytes_string;
			uint32_t type_name_index = this->resolve_stream_index(row_iter, stream_type::string, &num_bytes_string);
			row_iter += num_bytes_string;
			uint32_t type_namespace_index = this->resolve_stream_index(row_iter, stream_type::string, &num_bytes_string);
			row_iter += num_bytes_string;

			// Perform sanity checking on the indices
			if (type_name_index > strings_heap.size() || type_namespace_index > strings_heap.size())
			{
				this->last_error_code = error_codes::heap_out_of_bounds;
				return false;
			}

			// Get index for Extends object.
			uint32_t extends_idx;
			const uint32_t table_id = this->get_type_def_or_ref_index(*(uint32_t*)row_iter, &extends_idx);
			if (table_id == -1)
			{
				this->last_error_code = error_codes::decoded_index_invalid_table;
				return false;
			}
			row_iter += this->get_type_def_or_ref_index_size(result);

			// Get field list index.
			uint32_t field_list_index;
			const uint32_t field_idx_size = this->get_field_index_size(result);
			if (field_idx_size == sizeof(uint16_t))
			{
				field_list_index = *(uint16_t*)row_iter;
			}
			else
			{
				field_list_index = *(uint32_t*)row_iter;
			}
			row_iter += field_idx_size;

			// Get method list index.
			uint32_t method_list_index;
			const uint32_t method_idx_size = this->get_methoddef_index_size(result);
			if (method_idx_size == sizeof(uint16_t))
			{
				method_list_index = *(uint16_t*)row_iter;
			}
			else
			{
				method_list_index = *(uint32_t*)row_iter;
			}
			row_iter += method_idx_size;

			// Store TypeDef objects for further analysis.
			result->typedefs.push_back(type_def((char*)&strings_heap[type_name_index], (char*)&strings_heap[type_namespace_index]));
		}
	}
	else if (index == METADATA_TABLE_PARAM)
	{

	}
	else if (index == METADATA_TABLE_CONSTANT)
	{

	}
	else if (index == METADATA_TABLE_DECL_SECURITY)
	{

	}
	else if (index == METADATA_TABLE_STANDALONE_SIG)
	{
		// Check for the minimum amount of required memory to read this table.
/*		if ((uint32_t)remaining < num_rows * sizeof(uint32_t))
		{
			this->last_error_code = error_codes::insufficient_buffer;
			return false;
		}

		// Process signature blobs.
		for (uint32_t i = 0; i < num_rows; ++i)
		{
			// Get index to signature blob.
			uint32_t num_bytes_blob;
			uint32_t signature_index = this->resolve_stream_index(row_iter, stream_type::blob, &num_bytes_blob);
			row_iter += num_bytes_blob;

			// Perform sanity checking on the index.
			if (signature_index > blob_heap.size())
			{
				this->last_error_code = error_codes::heap_out_of_bounds;
				return false;
			}

			// FIXME: do something with signature blob.
		}
*/	}
	else if (index == METADATA_TABLE_PROPERTY_MAP)
	{

	}
	else if (index == METADATA_TABLE_METHOD_IMPL)
	{

	}
	else if (index == METADATA_TABLE_IMPL_MAP)
	{

	}
	else if (index == METADATA_TABLE_ASSEMBLY_PROCESSOR)
	{

	}
	else if (index == METADATA_TABLE_ASSEMBLY_REF_PROCESSOR)
	{

	}
	else if (index == METADATA_TABLE_EXPORTED_TYPE)
	{

	}
	else if (index == METADATA_TABLE_GENERIC_PARAM)
	{

	}
	else if (index == METADATA_TABLE_METHOD_SPEC)
	{

	}
	else
	{
		// Unknown table ID encountered.
		this->last_error_code = error_codes::invalid_stream_header;
		return false;
	}

	// Set number of bytes processed based on how much the row iterator has shifted.
	*bytes_processed = (uint32_t)(row_iter - row_iter_begin);

	// Still here, so table parsed successfully.
	return true;
}

// Resolve a metadata token to a human readable representation.

// Parse the entire metadata structure in the binary file under analysis.
bool metadata_parser::parse(analysis_result* const result)
{
	// Check if there is enough data to read the stream header.
	if (this->stream_length < sizeof(metadata_stream_header))
	{
		this->last_error_code = error_codes::insufficient_buffer;
		return false;
	}

	// Get the metadata stream header and obtain the index sizes.
	const metadata_stream_header* hdr = (metadata_stream_header*)this->tilde_stream;
	this->string_index_size = (hdr->HeapOffsetSizes & 1) ? sizeof(uint32_t) : sizeof(uint16_t);
	this->guid_index_size = (hdr->HeapOffsetSizes & 2) ? sizeof(uint32_t) : sizeof(uint16_t);
	this->blob_index_size = (hdr->HeapOffsetSizes & 4) ? sizeof(uint32_t) : sizeof(uint16_t);
	const uint64_t valid = hdr->Valid;
	int32_t remaining = this->stream_length - sizeof(metadata_stream_header);

	// Get the metadata tables that are actually present inside the binary.
	uint32_t num_tables = 0;

	// There are only 45 tabls defined, between 0 and 44.
	for (uint32_t i = 0; i < 64; i++)
	{
		// Test whether this table is present or not.
		// Note that we must make sure '1 << i' is a 64-bit integer or the masking won't work.
		if (valid & ((uint64_t)1 << i))
		{
			// Increment the number of tables and read the number of rows from memory.
			num_tables++;
		}
	}

	// There seems to be an 'extra data' flag that results in an extra DWORD. Skip it if present.
	if (hdr->HeapOffsetSizes & 0x40) ++num_tables;

	// Check if there is enough buffer to read the table descriptors.
	if ((uint32_t)remaining < num_tables * sizeof(uint32_t))
	{
		this->last_error_code = error_codes::insufficient_buffer;
		return false;
	}

	// Obtain the row counts of the tables.
	const uint32_t* dwords_ptr = (uint32_t*)(this->tilde_stream + sizeof(metadata_stream_header));
	uint32_t j = 0;
	for (uint32_t i = 0; i < 64; i++)
	{
		// Test whether this table is present or not.
		if (valid & ((uint64_t)1 << i))
		{
			// Increment the number of tables and read the number of rows from memory.
			result->metadata_tables[i] = dwords_ptr[j++];
		}
	}

	// Now iterate through the tables stored in the analysis result and read the contents.
	// Mind the pointer arithmetic below.
	const uint8_t* rows_offset = (uint8_t*)(dwords_ptr + num_tables);
	remaining -= num_tables * sizeof(uint32_t);
	for (auto const& table : result->metadata_tables)
	{
		// Parse the current table.
		uint32_t bytes_processed;
		if (!this->parse_table(table.first, table.second, rows_offset, remaining, &bytes_processed, result))
		{
			// Unknown table ID encountered or ran out of memory in input buffer.
			return false;
		}

		// Increment the rows pointer with the number of bytes processed here.
		rows_offset += bytes_processed;
		remaining -= bytes_processed;

		// If no bytes are available for reading anymore, we will stop.
		if (remaining <= 0) break;
	}

	// Everything went well!
	this->last_error_code = error_codes::success;
	return true;
}

error_codes metadata_parser::get_last_error() const
{
	return this->last_error_code;
}
