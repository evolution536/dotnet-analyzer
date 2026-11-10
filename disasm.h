#pragma once

#include <cstdint>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstring>

// Defintions for single byte instructions.
#define INSN_NOP			0x00
#define INSN_BREAK			0x01
#define INSN_LDARG_0		0x02
#define INSN_LDARG_1		0x03
#define INSN_LDARG_2		0x04
#define INSN_LDARG_3		0x05
#define	INSN_LDLOC_0		0x06
#define INSN_LDLOC_1		0x07
#define INSN_LDLOC_2		0x08
#define INSN_LDLOC_3		0x09
#define INSN_STLOC_0		0x0A
#define INSN_STLOC_1		0x0B
#define INSN_STLOC_2		0x0C
#define INSN_STLOC_3		0x0D
#define INSN_LDARG_S		0x0E
#define INSN_LDARGA_S		0x0F
#define INSN_STARG_S		0x10
#define INSN_LDLOC_S		0x11
#define INSN_LDLOCA_S		0x12
#define INSN_STLOC_S		0x13
#define INSN_LDNULL			0x14
#define INSN_LDC_I4_M1		0x15
#define INSN_LDC_I4_0		0x16
#define INSN_LDC_I4_1		0x17
#define INSN_LDC_I4_2		0x18
#define INSN_LDC_I4_3		0x19
#define INSN_LDC_I4_4		0x1A
#define INSN_LDC_I4_5		0x1B
#define INSN_LDC_I4_6		0x1C
#define INSN_LDC_I4_7		0x1D
#define INSN_LDC_I4_8		0x1E
#define INSN_LDC_I4_S		0x1F
#define INSN_LDC_I4			0x20
#define INSN_LDC_I8			0x21
#define INSN_LDC_R4			0x22
#define INSN_LDC_R8			0x23
#define INSN_DUP			0x25
#define INSN_POP			0x26
#define INSN_JMP			0x27
#define INSN_CALL			0x28
#define INSN_CALLI			0x29
#define INSN_RET			0x2A
#define INSN_BR_S			0x2B
#define INSN_BRFALSE_S		0x2C
#define INSN_BRTRUE_S		0x2D
#define INSN_BEQ_S			0x2E
#define INSN_BGE_S			0x2F
#define INSN_BGT_S			0x30
#define INSN_BLE_S			0x31
#define INSN_BLT_S			0x32
#define INSN_BNE_UN_S		0x33
#define INSN_BGE_UN_S		0x34
#define INSN_BGT_UN_S		0x35
#define INSN_BLE_UN_S		0x36
#define INSN_BLT_UN_S		0x37
#define INSN_BR				0x38
#define INSN_BRFALSE		0x39
#define INSN_BRTRUE			0x3A
#define INSN_BEQ			0x3B
#define INSN_BGE			0x3C
#define INSN_BGT			0x3D
#define INSN_BLE			0x3E
#define INSN_BLT			0x3F
#define INSN_BNE_UN			0x40
#define INSN_BGE_UN			0x41
#define INSN_BGT_UN			0x42
#define INSN_BLE_UN			0x43
#define INSN_BLT_UN			0x44
#define INSN_SWITCH			0x45
#define INSN_LDIND_I1		0x46
#define INSN_LDIND_U1		0x47
#define INSN_LDIND_I2		0x48
#define INSN_LDIND_U2		0x49
#define INSN_LDIND_I4		0x4A
#define INSN_LDIND_U4		0x4B
#define INSN_LDIND_I8		0x4C
#define INSN_LDIND_I		0x4D
#define INSN_LDIND_R4		0x4E
#define INSN_LDIND_R8		0x4F
#define INSN_LDIND_REF		0x50
#define INSN_STIND_REF		0x51
#define INSN_STIND_I1		0x52
#define INSN_STIND_I2		0x53
#define INSN_STIND_I4		0x54
#define INSN_STIND_I8		0x55
#define INSN_STIND_R4		0x56
#define INSN_STIND_R8		0x57
#define INSN_ADD			0x58
#define INSN_SUB			0x59
#define INSN_MUL			0x5A
#define INSN_DIV			0x5B
#define INSN_DIV_UN			0x5C
#define INSN_REM			0x5D
#define INSN_REM_UN			0x5E
#define INSN_AND			0x5F
#define INSN_OR				0x60
#define INSN_XOR			0x61
#define INSN_SHL			0x62
#define INSN_SHR			0x63
#define INSN_SHR_UN			0x64
#define INSN_NEG			0x65
#define INSN_NOT			0x66
#define INSN_CONV_I1		0x67
#define INSN_CONV_I2		0x68
#define INSN_CONV_I4		0x69
#define INSN_CONV_I8		0x6A
#define	INSN_CONV_R4		0x6B
#define INSN_CONV_R8		0x6C
#define INSN_CONV_U4		0x6D
#define INSN_CONV_U8		0x6E
#define INSN_CALLVIRT		0x6F
#define INSN_CPOBJ			0x70
#define INSN_LDOBJ			0x71
#define INSN_LDSTR			0x72
#define INSN_NEWOBJ			0x73
#define INSN_CASTCLASS		0x74
#define INSN_ISINST			0x75
#define INSN_CONV_R_UN		0x76
#define INSN_UNBOX			0x79
#define INSN_THROW			0x7A
#define INSN_LDFLD			0x7B
#define INSN_LDFLD_A		0x7C
#define INSN_STFLD			0x7D
#define INSN_LDSFLD			0x7E
#define INSN_LDSFLD_A		0x7F
#define INSN_STSFLD			0x80
#define INSN_STOBJ			0x81
#define INSN_CONV_OVF_I1_UN	0x82
#define INSN_CONV_OVF_I2_UN	0x83
#define INSN_CONV_OVF_I4_UN	0x84
#define INSN_CONV_OVF_I8_UN	0x85
#define INSN_CONV_OVF_U1_UN	0x86
#define INSN_CONV_OVF_U2_UN	0x87
#define INSN_CONV_OVF_U4_UN	0x88
#define INSN_CONV_OVF_U8_UN	0x89
#define INSN_CONV_OVF_I_UN	0x8A
#define INSN_CONV_OVF_U_UN	0x8B
#define INSN_BOX			0x8C
#define INSN_NEWARR			0x8D
#define INSN_LDLEN			0x8E
#define INSN_LDELEMA		0x8F
#define INSN_LDELEM_I1		0x90
#define INSN_LDELEM_U1		0x91
#define INSN_LDELEM_I2		0x92
#define INSN_LDELEM_U2		0x93
#define INSN_LDELEM_I4		0x94
#define INSN_LDELEM_U4		0x95
#define INSN_LDELEM_I8		0x96
#define INSN_LDELEM_I		0x97
#define INSN_LDELEM_R4		0x98
#define INSN_LDELEM_R8		0x99
#define INSN_LDELEM_REF		0x9A
#define INSN_STELEM_I		0x9B
#define INSN_STELEM_I1		0x9C
#define INSN_STELEM_I2		0x9D
#define INSN_STELEM_I4		0x9E
#define INSN_STELEM_I8		0x9F
#define INSN_STELEM_R4		0xA0
#define INSN_STELEM_R8		0xA1
#define INSN_STELEM_REF		0xA2
#define INSN_LDELEM			0xA3
#define INSN_STELEM			0xA4
#define INSN_UNBOX_ANY		0xA5
#define INSN_CONV_OVF_I1	0xB3
#define INSN_CONV_OVF_U1	0xB4
#define INSN_CONV_OVF_I2	0xB5
#define INSN_CONV_OVF_U2	0xB6
#define INSN_CONV_OVF_I4	0xB7
#define INSN_CONV_OVF_U4	0xB8
#define INSN_CONV_OVF_I8	0xB9
#define INSN_CONV_OVF_U8	0xBA
#define INSN_REFANYVAL		0xC2
#define INSN_CKFINITE		0xC3
#define INSN_MKREFANY		0xC6
#define INSN_LDTOKEN		0xD0
#define INSN_CONV_U2		0xD1
#define INSN_CONV_U1		0xD2
#define INSN_CONV_I			0xD3
#define INSN_CONV_OVF_I		0xD4
#define INSN_CONV_OVF_U		0xD5
#define INSN_ADD_OVF		0xD6
#define INSN_ADD_OVF_UN		0xD7
#define INSN_MUL_OVF		0xD8
#define INSN_MUL_OVF_UN		0xD9
#define INSN_SUB_OVF		0xDA
#define INSN_SUB_OVF_UN		0xDB
#define INSN_ENDFINALLY		0xDC
#define INSN_LEAVE			0xDD
#define INSN_LEAVE_S		0xDE
#define INSN_STIND_I		0xDF
#define INSN_CONV_U			0xE0

// The following byte opcode indicates that the instruction is encoded in two bytes.
#define OPCODE_HAS_NEXT		0xFE

// The following byte opcodes are used as second bytes encoded.
#define OPCODE_ARGLIST		0x00
#define OPCODE_CEQ			0x01
#define OPCODE_CGT			0x02
#define OPCODE_CGT_UN		0x03
#define OPCODE_CLT			0x04
#define OPCODE_CLT_UN		0x05
#define OPCODE_LDFTN		0x06
#define OPCODE_LDVIRTFTN	0x07
#define OPCODE_LDARG		0x09
#define OPCODE_LDARGA		0x0A
#define OPCODE_STARG		0x0B
#define OPCODE_LDLOC		0x0C
#define OPCODE_LDLOCA		0x0D
#define OPCODE_STLOC		0x0E
#define OPCODE_LOCALLOC		0x0F
#define OPCODE_ENDFILTER	0x11
#define OPCODE_UNALIGNED_	0x12
#define OPCODE_VOLATILE_	0x13
#define OPCODE_TAIL_		0x14
#define OPCODE_INITOBJ		0x15
#define OPCODE_CONSTRAINED_	0x16
#define OPCODE_CPBLK		0x17
#define OPCODE_INITBLK		0x18
#define OPCODE_NO_			0x19
#define OPCODE_RETHROW		0x1A
#define OPCODE_SIZEOF		0x1C
#define OPCODE_REFANYTYPE	0x1D
#define OPCODE_READONLY_	0x1E

// Instruction storage object.
struct instruction
{
	// Offset in bytes from the start of the method body.
	uint32_t offset;

	// Instruction opcodes.
	uint8_t opcodes[4];

	// Number of opcode bytes, at most 4.
	uint32_t num_opcode_bytes;

	// Stores the operand value.
	uint64_t operand;

	// Length of operand value, in bytes.
	uint32_t operand_length;

	// Indicates whether the operand is a metadata token or not.
	bool has_metadata_token;

	// Instruction length.
	uint32_t insn_length;

	// Mnemonics of instruction.
	char mnemonics[32];

	// Default constructor.
	instruction()
	{
		this->offset = 0;
		memset(this->opcodes, 0, sizeof(this->opcodes));
		this->num_opcode_bytes = 0;
		this->operand = 0;
		this->operand_length = 0;
		this->insn_length = 0;
		this->has_metadata_token = false;
		memset(this->mnemonics, 0, sizeof(this->mnemonics));
	};

	// Default to string method for printing.
	std::string to_string() const
	{
		std::stringstream ss;
		ss << this->mnemonics;
		if (this->operand && this->operand_length > 0)
		{
			ss << " 0x" << std::setfill('0') << std::setw((std::streamsize)this->operand_length << 1) << this->operand;
		}
		return ss.str();
	};
};

// Main disassembler function. Returns instruction in referenced parameter, and number of bytes processed in the return value.
uint32_t disasm(const uint8_t* buffer, const int32_t remaining, instruction& insn);
