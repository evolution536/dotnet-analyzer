#pragma once

#include <cstdint>

#define	IMAGE_FILE_MACHINE_I386		0x014c
#define	IMAGE_FILE_MACHINE_AMD64	0x8664

#pragma pack(push, 1)
typedef struct {
    uint16_t  e_magic;      /* 00: MZ Header signature */
    uint16_t  e_cblp;       /* 02: Bytes on last page of file */
    uint16_t  e_cp;         /* 04: Pages in file */
    uint16_t  e_crlc;       /* 06: Relocations */
    uint16_t  e_cparhdr;    /* 08: Size of header in paragraphs */
    uint16_t  e_minalloc;   /* 0a: Minimum extra paragraphs needed */
    uint16_t  e_maxalloc;   /* 0c: Maximum extra paragraphs needed */
    uint16_t  e_ss;         /* 0e: Initial (relative) SS value */
    uint16_t  e_sp;         /* 10: Initial SP value */
    uint16_t  e_csum;       /* 12: Checksum */
    uint16_t  e_ip;         /* 14: Initial IP value */
    uint16_t  e_cs;         /* 16: Initial (relative) CS value */
    uint16_t  e_lfarlc;     /* 18: File address of relocation table */
    uint16_t  e_ovno;       /* 1a: Overlay number */
    uint16_t  e_res[4];     /* 1c: Reserved uint16_ts */
    uint16_t  e_oemid;      /* 24: OEM identifier (for e_oeminfo) */
    uint16_t  e_oeminfo;    /* 26: OEM information; e_oemid specific */
    uint16_t  e_res2[10];   /* 28: Reserved uint16_ts */
    uint32_t e_lfanew;     /* 3c: Offset to extended header */
} IMAGE_DOS_HEADER32, *PIMAGE_DOS_HEADER32;

typedef struct {
  uint16_t  Machine;
  uint16_t  NumberOfSections;
  uint32_t TimeDateStamp;
  uint32_t PointerToSymbolTable;
  uint32_t NumberOfSymbols;
  uint16_t  SizeOfOptionalHeader;
  uint16_t  Characteristics;
} IMAGE_FILE_HEADER32, *PIMAGE_FILE_HEADER32;

typedef struct {
  uint32_t VirtualAddress;
  uint32_t Size;
} IMAGE_DATA_DIRECTORY32, *PIMAGE_DATA_DIRECTORY32;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _IMAGE_OPTIONAL_HEADER64 {
  uint16_t  Magic; /* 0x20b */
  uint8_t MajorLinkerVersion;
  uint8_t MinorLinkerVersion;
  uint32_t SizeOfCode;
  uint32_t SizeOfInitializedData;
  uint32_t SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint;
  uint32_t BaseOfCode;
  uint64_t ImageBase;
  uint32_t SectionAlignment;
  uint32_t FileAlignment;
  uint16_t MajorOperatingSystemVersion;
  uint16_t MinorOperatingSystemVersion;
  uint16_t MajorImageVersion;
  uint16_t MinorImageVersion;
  uint16_t MajorSubsystemVersion;
  uint16_t MinorSubsystemVersion;
  uint32_t Win32VersionValue;
  uint32_t SizeOfImage;
  uint32_t SizeOfHeaders;
  uint32_t CheckSum;
  uint16_t Subsystem;
  uint16_t DllCharacteristics;
  uint64_t SizeOfStackReserve;
  uint64_t SizeOfStackCommit;
  uint64_t SizeOfHeapReserve;
  uint64_t SizeOfHeapCommit;
  uint32_t LoaderFlags;
  uint32_t NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY32 DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
  uint32_t Signature;
  IMAGE_FILE_HEADER32 FileHeader;
  IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_OPTIONAL_HEADER {

  /* Standard fields */

  uint16_t  Magic; /* 0x10b or 0x107 */	/* 0x00 */
  uint8_t  MajorLinkerVersion;
  uint8_t  MinorLinkerVersion;
  uint32_t SizeOfCode;
  uint32_t SizeOfInitializedData;
  uint32_t SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint;		/* 0x10 */
  uint32_t BaseOfCode;
  uint32_t BaseOfData;

  /* NT additional fields */

  uint32_t ImageBase;
  uint32_t SectionAlignment;		/* 0x20 */
  uint32_t FileAlignment;
  uint16_t  MajorOperatingSystemVersion;
  uint16_t  MinorOperatingSystemVersion;
  uint16_t  MajorImageVersion;
  uint16_t  MinorImageVersion;
  uint16_t  MajorSubsystemVersion;		/* 0x30 */
  uint16_t  MinorSubsystemVersion;
  uint32_t Win32VersionValue;
  uint32_t SizeOfImage;
  uint32_t SizeOfHeaders;
  uint32_t CheckSum;			/* 0x40 */
  uint16_t  Subsystem;
  uint16_t  DllCharacteristics;
  uint32_t SizeOfStackReserve;
  uint32_t SizeOfStackCommit;
  uint32_t SizeOfHeapReserve;		/* 0x50 */
  uint32_t SizeOfHeapCommit;
  uint32_t LoaderFlags;
  uint32_t NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY32 DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]; /* 0x60 */
  /* 0xE0 */
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_NT_HEADERS {
  uint32_t Signature; /* "PE"\0\0 */	/* 0x00 */
  IMAGE_FILE_HEADER32 FileHeader;		/* 0x04 */
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;	/* 0x18 */
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct {
    uint32_t cb;
    uint16_t  MajorRuntimeVersion;
    uint16_t  MinorRuntimeVersion;

    IMAGE_DATA_DIRECTORY32 MetaData;
    uint32_t Flags;
    union {
        uint32_t EntryPointToken;
        uint32_t EntryPointRVA;
    };

    IMAGE_DATA_DIRECTORY32 Resources;
    IMAGE_DATA_DIRECTORY32 StrongNameSignature;
    IMAGE_DATA_DIRECTORY32 CodeManagerTable;
    IMAGE_DATA_DIRECTORY32 VTableFixups;
    IMAGE_DATA_DIRECTORY32 ExportAddressTableJumps;
    IMAGE_DATA_DIRECTORY32 ManagedNativeHeader;
} IMAGE_COR20_HEADER32, *PIMAGE_COR20_HEADER32;

typedef struct {
  uint8_t  Name[8];
  union {
    uint32_t PhysicalAddress;
    uint32_t VirtualSize;
  } Misc;
  uint32_t VirtualAddress;
  uint32_t SizeOfRawData;
  uint32_t PointerToRawData;
  uint32_t PointerToRelocations;
  uint32_t PointerToLinenumbers;
  uint16_t  NumberOfRelocations;
  uint16_t  NumberOfLinenumbers;
  uint32_t Characteristics;
} IMAGE_SECTION_HEADER32, *PIMAGE_SECTION_HEADER32;
#pragma pack(pop)
