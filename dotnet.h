#pragma once

// Represents the header of the metadata (~) stream.
#pragma pack(push, 1)
struct metadata_stream_header
{
	uint32_t Reserved0;
	uint8_t MajorVersion;
	uint8_t MinorVersion;
	uint8_t HeapOffsetSizes;
	uint8_t Reserved1;
	uint64_t Valid;
	uint64_t Sorted;
};
#pragma pack(pop)