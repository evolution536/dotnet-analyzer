#include "disasm.h"
#include <cstring>

// Disassembles STIND instructions having a single byte.
static uint32_t disasm_stind_instruction(const uint8_t* buffer, const int32_t remaining, char* mnemonics)
{
	if (*buffer == INSN_STIND_I1)
	{
		strcpy_s(mnemonics, 32, "stind.i1");
	}
	else if (*buffer == INSN_STIND_I2)
	{
		strcpy_s(mnemonics, 32, "stind.i2");
	}
	else if (*buffer == INSN_STIND_I4)
	{
		strcpy_s(mnemonics, 32, "stind.i4");
	}
	else if (*buffer == INSN_STIND_I8)
	{
		strcpy_s(mnemonics, 32, "stind.i8");
	}
	else if (*buffer == INSN_STIND_R4)
	{
		strcpy_s(mnemonics, 32, "stind.r4");
	}
	else if (*buffer == INSN_STIND_R8)
	{
		strcpy_s(mnemonics, 32, "stind.r8");
	}
	else if (*buffer == INSN_STIND_I)
	{
		strcpy_s(mnemonics, 32, "stind.i");
	}
	else if (*buffer == INSN_STIND_REF)
	{
		strcpy_s(mnemonics, 32, "stind.ref");
	}

	return 1;
}

// Disassembles the switch instruction and its jump table.
static uint32_t disasm_switch_instruction(const uint8_t* buffer, const int32_t remaining, instruction& insn, char* mnemonics)
{
	// We need at least the uint32 that hands us over the number of successive entries.
	if (remaining < 5) return 0;

	// Get number of jump table entries and test the available memory. Since we are casting and calculating signed integers,
	// make sure we don't hit an integer overflow or underflow.
	const uint32_t num_entries = *((uint32_t*)&buffer[1]);
	if (num_entries > 0x1FFFFFFF) return 0;
	if (remaining < (int32_t)(5 + num_entries * sizeof(int32_t))) return 0;

	// For now, we will just set the mnemonics and return the instruction properties required for length disassembly.
	strcpy_s(mnemonics, 32, "switch");
	insn.operand_length = sizeof(uint32_t) + num_entries * sizeof(int32_t);
	return 5 + num_entries * sizeof(int32_t);
}

// Disassembles LDARG or LDARGA instructions.
static uint32_t disasm_ld_st_instruction(const uint8_t opcode, const uint8_t* buffer, const int32_t remaining, instruction& insn, char* mnemonics)
{
	// Check if there is enough memory available for the operand.
	if (remaining < 4) return 0;

	if (opcode == OPCODE_LDARG)
	{
		strcpy_s(mnemonics, 32, "ldarg");
	}
	else if (opcode == OPCODE_LDARGA)
	{
		strcpy_s(mnemonics, 32, "ldarga");
	}
	else if (opcode == OPCODE_STARG)
	{
		strcpy_s(mnemonics, 32, "starg");
	}
	else if (opcode == OPCODE_LDLOC)
	{
		strcpy_s(mnemonics, 32, "ldloc");
	}
	else if (opcode == OPCODE_LDLOCA)
	{
		strcpy_s(mnemonics, 32, "ldloca");
	}
	else if (opcode == OPCODE_STLOC)
	{
		strcpy_s(mnemonics, 32, "stloc");
	}

	// Set instruction properties.
	insn.operand = *((uint16_t*)&buffer[2]);
	insn.operand_length = sizeof(uint16_t);
	return 4;
}

// Disassembles a dual-byte instruction having a metadata token as argument.
static uint32_t disasm_token_dual_instruction(const uint8_t opcode, const uint8_t* buffer, const int32_t remaining, instruction& insn, char* mnemonics)
{
	// We need enough available memory for the metadata token operand.
	if (remaining < 6) return 0;

	// Set the correct name of the instruction.
	switch (opcode)
	{
	case OPCODE_SIZEOF:
		strcpy_s(mnemonics, 32, "sizeof");
		break;
	case OPCODE_LDFTN:
		strcpy_s(mnemonics, 32, "ldftn");
		break;
	case OPCODE_LDVIRTFTN:
		strcpy_s(mnemonics, 32, "ldvirtftn");
		break;
	}

	// Set instruction properties.
	insn.operand = *(uint32_t*)(buffer + 2);
	insn.operand_length = sizeof(uint32_t);
	return 6;
}

// Disassembles instructions having a single byte and metadata token as operand.
static uint32_t disasm_token_single_instruction(const uint8_t opcode, const uint8_t* buffer, const int32_t remaining, instruction& insn, char* mnemonics)
{
	// We need enough available memory for the metadata token operand.
	if (remaining < 5) return 0;

	// Set the correct name of the instruction.
	switch (opcode)
	{
	case INSN_LDFLD:
		strcpy_s(mnemonics, 32, "ldfld");
		break;
	case INSN_CALL:
		strcpy_s(mnemonics, 32, "call");
		break;
	case INSN_CALLI:
		strcpy_s(mnemonics, 32, "calli");
		break;
	case INSN_STELEM:
		strcpy_s(mnemonics, 32, "stelem");
		break;
	case INSN_LDELEM:
		strcpy_s(mnemonics, 32, "ldelem");
		break;
	case INSN_LDELEMA:
		strcpy_s(mnemonics, 32, "ldelema");
		break;
	case INSN_LDOBJ:
		strcpy_s(mnemonics, 32, "ldobj");
		break;
	case INSN_LDSTR:
		strcpy_s(mnemonics, 32, "ldstr");
		break;
	case INSN_LDTOKEN:
		strcpy_s(mnemonics, 32, "ldtoken");
		break;
	case INSN_ISINST:
		strcpy_s(mnemonics, 32, "isinst");
		break;
	case INSN_CPOBJ:
		strcpy_s(mnemonics, 32, "cpobj");
		break;
	case INSN_CASTCLASS:
		strcpy_s(mnemonics, 32, "castclass");
		break;
	case INSN_CALLVIRT:
		strcpy_s(mnemonics, 32, "callvirt");
		break;
	case INSN_BOX:
		strcpy_s(mnemonics, 32, "box");
		break;
	case INSN_NEWARR:
		strcpy_s(mnemonics, 32, "newarr");
		break;
	case INSN_NEWOBJ:
		strcpy_s(mnemonics, 32, "newobj");
		break;
	case INSN_STOBJ:
		strcpy_s(mnemonics, 32, "stobj");
		break;
	case INSN_STFLD:
		strcpy_s(mnemonics, 32, "stfld");
		break;
	case INSN_STSFLD:
		strcpy_s(mnemonics, 32, "stsfld");
		break;
	case INSN_UNBOX:
		strcpy_s(mnemonics, 32, "unbox");
		break;
	case INSN_UNBOX_ANY:
		strcpy_s(mnemonics, 32, "unbox.any");
		break;
	case INSN_LDSFLD:
		strcpy_s(mnemonics, 32, "ldsfld");
		break;
	case INSN_LDSFLD_A:
		strcpy_s(mnemonics, 32, "ldsflda");
		break;
	case INSN_JMP:
		strcpy_s(mnemonics, 32, "jmp");
		break;
	}

	// Set instruction properties.
	insn.operand = *(uint32_t*)(buffer + 1);
	insn.operand_length = sizeof(uint32_t);
	return 5;
}

// Disassembles branch instructions having a full, 4-byte operand.
static uint32_t disasm_long_branch_instruction(const uint8_t opcode, const uint8_t* buffer, const int32_t remaining, instruction& insn, char* mnemonics)
{
	// We need enough available memory for the metadata token operand.
	if (remaining < 5) return 0;

	// Set the correct name of the instruction.
	switch (opcode)
	{
	case INSN_BR:
		strcpy_s(mnemonics, 32, "br");
		break;
	case INSN_BEQ:
		strcpy_s(mnemonics, 32, "beq");
		break;
	case INSN_BGE:
		strcpy_s(mnemonics, 32, "bge");
		break;
	case INSN_BGE_UN:
		strcpy_s(mnemonics, 32, "bge.un");
		break;
	case INSN_BGT:
		strcpy_s(mnemonics, 32, "bgt");
		break;
	case INSN_BGT_UN:
		strcpy_s(mnemonics, 32, "bgt.un");
		break;
	case INSN_BLE:
		strcpy_s(mnemonics, 32, "ble");
		break;
	case INSN_BLE_UN:
		strcpy_s(mnemonics, 32, "ble.un");
		break;
	case INSN_BLT:
		strcpy_s(mnemonics, 32, "blt");
		break;
	case INSN_BLT_UN:
		strcpy_s(mnemonics, 32, "blt.un");
		break;
	case INSN_BNE_UN:
		strcpy_s(mnemonics, 32, "bne.un");
		break;
	case INSN_BRFALSE:
		strcpy_s(mnemonics, 32, "brfalse");
		break;
	case INSN_BRTRUE:
		strcpy_s(mnemonics, 32, "brtrue");
		break;
	case INSN_LDC_I4:
		strcpy_s(mnemonics, 32, "ldc.i4");
		break;
	case INSN_LDC_R4:
		strcpy_s(mnemonics, 32, "ldc.r4");
		break;
	case INSN_LEAVE:
		strcpy_s(mnemonics, 32, "leave");
		break;
	}

	// Set instruction properties.
	insn.operand = *(uint32_t*)(buffer + 1);
	insn.operand_length = sizeof(uint32_t);
	return 5;
}

// Disassembles branch instructions having a short, 1-byte operand.
static uint32_t disasm_short_branch_instruction(const uint8_t opcode, const uint8_t* buffer, const int32_t remaining, instruction& insn, char* mnemonics)
{
	// We need enough available memory for the metadata token operand.
	if (remaining < 2) return 0;

	// Set the correct name of the instruction.
	switch (opcode)
	{
	case INSN_BR_S:
		strcpy_s(mnemonics, 32, "br.s");
		break;
	case INSN_BEQ_S:
		strcpy_s(mnemonics, 32, "beq.s");
		break;
	case INSN_BGE_S:
		strcpy_s(mnemonics, 32, "bge.s");
		break;
	case INSN_BGE_UN_S:
		strcpy_s(mnemonics, 32, "bge.un.s");
		break;
	case INSN_BGT_S:
		strcpy_s(mnemonics, 32, "bgt.s");
		break;
	case INSN_BGT_UN_S:
		strcpy_s(mnemonics, 32, "bgt.un.s");
		break;
	case INSN_BLE_S:
		strcpy_s(mnemonics, 32, "ble.s");
		break;
	case INSN_BLE_UN_S:
		strcpy_s(mnemonics, 32, "ble.un.s");
		break;
	case INSN_BLT_S:
		strcpy_s(mnemonics, 32, "blt.s");
		break;
	case INSN_BLT_UN_S:
		strcpy_s(mnemonics, 32, "blt.un.s");
		break;
	case INSN_BNE_UN_S:
		strcpy_s(mnemonics, 32, "bne.un.s");
		break;
	case INSN_BRFALSE_S:
		strcpy_s(mnemonics, 32, "brfalse.s");
		break;
	case INSN_BRTRUE_S:
		strcpy_s(mnemonics, 32, "brtrue.s");
		break;
	case INSN_LDC_I4_S:
		strcpy_s(mnemonics, 32, "ldc.i4.s");
		break;
	case INSN_STLOC_S:
		strcpy_s(mnemonics, 32, "stloc.s");
		break;
	case INSN_LDLOC_S:
		strcpy_s(mnemonics, 32, "ldloc.s");
		break;
	case INSN_LEAVE_S:
		strcpy_s(mnemonics, 32, "leave.s");
		break;
	}

	// Set instruction properties.
	insn.operand = *(buffer + 1);
	insn.operand_length = sizeof(uint8_t);
	return 2;
}

// Disassembles  instructions having a long long, 8-byte operand.
static uint32_t disasm_long_long_instruction(const uint8_t opcode, const uint8_t* buffer, const int32_t remaining, instruction& insn, char* mnemonics)
{
	// We need enough available memory for the metadata token operand.
	if (remaining < 9) return 0;

	// Set the correct name of the instruction.
	switch (opcode)
	{
	case INSN_LDC_I8:
		strcpy_s(mnemonics, 32, "ldc.i8");
		break;
	case INSN_LDC_R8:
		strcpy_s(mnemonics, 32, "ldc.r8");
		break;
	}

	// Set instruction properties.
	insn.operand = *(uint64_t*)(buffer + 1);
	insn.operand_length = sizeof(uint64_t);
	return 9;
}

// Disassembles the next code at 'buffer'. Returns number of bytes processed or zero if no instruction has been disassembled.
uint32_t disasm(const uint8_t* buffer, const int32_t remaining, instruction& insn)
{
	// No bytes is no instructions.
	if (remaining < 1) return 0;
	
	// Get next byte and test for encoded opcodes.
	const uint8_t next = *buffer;
	char mnemonics[32] = { 0 };
	uint32_t insn_length = 0;
	if (next == OPCODE_HAS_NEXT)
	{
		// We need to parse the second byte.
		if (remaining < 2) return 0;

		// Read next byte and parse the instruction.
		const uint8_t second_byte = buffer[1];
		switch (second_byte)
		{
		case OPCODE_ARGLIST:
			insn_length = 2;
			strcpy_s(mnemonics, "arglist");
			break;
		case OPCODE_CEQ:
			insn_length = 2;
			strcpy_s(mnemonics, "ceq");
			break;
		case OPCODE_CGT:
			insn_length = 2;
			strcpy_s(mnemonics, "cgt");
			break;
		case OPCODE_CGT_UN:
			insn_length = 2;
			strcpy_s(mnemonics, "cgt.un");
			break;
		case OPCODE_CLT:
			insn_length = 2;
			strcpy_s(mnemonics, "clt");
			break;
		case OPCODE_CLT_UN:
			insn_length = 2;
			strcpy_s(mnemonics, "clt.un");
			break;
		case OPCODE_LOCALLOC:
			insn_length = 2;
			strcpy_s(mnemonics, "localloc");
			break;
		case OPCODE_RETHROW:
			insn_length = 2;
			strcpy_s(mnemonics, "rethrow");
			break;
		case OPCODE_CPBLK:
			insn_length = 2;
			strcpy_s(mnemonics, "cpblk");
			break;
		case OPCODE_LDFTN:
		case OPCODE_LDVIRTFTN:
		case OPCODE_SIZEOF:
			insn_length = disasm_token_dual_instruction(second_byte, buffer, remaining, insn, mnemonics);
			break;
		case OPCODE_LDARG:
		case OPCODE_LDARGA:
		case OPCODE_STARG:
		case OPCODE_LDLOC:
		case OPCODE_LDLOCA:
		case OPCODE_STLOC:
			insn_length = disasm_ld_st_instruction(second_byte, buffer, remaining, insn, mnemonics);
			break;
		case OPCODE_ENDFILTER:
			insn_length = 2;
			strcpy_s(mnemonics, "endfilter");
			break;
		case OPCODE_INITBLK:
			insn_length = 2;
			strcpy_s(mnemonics, "initblk");
			break;
		case OPCODE_UNALIGNED_:
			if (remaining < 3) return 0;
			insn_length = 3;
			strcpy_s(mnemonics, "unaligned.");
			insn.operand = buffer[2];
			insn.operand_length = sizeof(uint8_t);
			break;
		case OPCODE_VOLATILE_:
			insn_length = 2;
			strcpy_s(mnemonics, "volatile.");
			break;
		}

		insn.num_opcode_bytes = 2;
	}
	else
	{
		// Decode the instruction at the next byte, if any.
		switch (next)
		{
		case INSN_CONV_I1:
			strcpy_s(mnemonics, 32, "conv.i1");
			insn_length = 1;
			break;
		case INSN_CONV_I2:
			strcpy_s(mnemonics, 32, "conv.i2");
			insn_length = 1;
			break;
		case INSN_CONV_I4:
			strcpy_s(mnemonics, 32, "conv.i4");
			insn_length = 1;
			break;
		case INSN_CONV_I8:
			strcpy_s(mnemonics, 32, "conv.i8");
			insn_length = 1;
			break;
		case INSN_CONV_R4:
			strcpy_s(mnemonics, 32, "conv.r4");
			insn_length = 1;
			break;
		case INSN_CONV_R8:
			strcpy_s(mnemonics, 32, "conv.r8");
			insn_length = 1;
			break;
		case INSN_CONV_U1:
			strcpy_s(mnemonics, 32, "conv.u1");
			insn_length = 1;
			break;
		case INSN_CONV_U2:
			strcpy_s(mnemonics, 32, "conv.u2");
			insn_length = 1;
			break;
		case INSN_CONV_U4:
			strcpy_s(mnemonics, 32, "conv.u4");
			insn_length = 1;
			break;
		case INSN_CONV_U8:
			strcpy_s(mnemonics, 32, "conv.u8");
			insn_length = 1;
			break;
		case INSN_CONV_I:
			strcpy_s(mnemonics, 32, "conv.i");
			insn_length = 1;
			break;
		case INSN_CONV_U:
			strcpy_s(mnemonics, 32, "conv.u");
			insn_length = 1;
			break;
		case INSN_CONV_R_UN:
			strcpy_s(mnemonics, 32, "conv.r.un");
			insn_length = 1;
			break;
		case INSN_CONV_OVF_I1:
			strcpy_s(mnemonics, 32, "conv.ovf.i1");
			insn_length = 1;
			break;
		case INSN_CONV_OVF_I2:
			strcpy_s(mnemonics, 32, "conv.ovf.i2");
			insn_length = 1;
			break;
		case INSN_CONV_OVF_I4:
			strcpy_s(mnemonics, 32, "conv.ovf.i4");
			insn_length = 1;
			break;
		case INSN_CONV_OVF_I8:
			strcpy_s(mnemonics, 32, "conv.ovf.i8");
			insn_length = 1;
			break;
		case INSN_CONV_OVF_U1:
			strcpy_s(mnemonics, 32, "conv.ovf.u1");
			insn_length = 1;
			break;
		case INSN_CONV_OVF_U2:
			strcpy_s(mnemonics, 32, "conv.ovf.u2");
			insn_length = 1;
			break;
		case INSN_CONV_OVF_U4:
			strcpy_s(mnemonics, 32, "conv.ovf.u4");
			insn_length = 1;
			break;
		case INSN_CONV_OVF_U8:
			strcpy_s(mnemonics, 32, "conv.ovf.u8");
			insn_length = 1;
			break;
		case INSN_CONV_OVF_I:
			strcpy_s(mnemonics, 32, "conv.ovf.i");
			insn_length = 1;
			break;
		case INSN_CONV_OVF_U:
			strcpy_s(mnemonics, 32, "conv.ovf.u");
			insn_length = 1;
			break;
		case INSN_CONV_OVF_I1_UN:
			strcpy_s(mnemonics, 32, "conv.ovf.i1.un");
			insn_length = 1;
			break;
		case INSN_CONV_OVF_I2_UN:
			strcpy_s(mnemonics, 32, "conv.ovf.i2.un");
			insn_length = 1;
			break;
		case INSN_CONV_OVF_I4_UN:
			strcpy_s(mnemonics, 32, "conv.ovf.i4.un");
			insn_length = 1;
			break;
		case INSN_CONV_OVF_I8_UN:
			strcpy_s(mnemonics, 32, "conv.ovf.i8.un");
			insn_length = 1;
			break;
		case INSN_CONV_OVF_U1_UN:
			strcpy_s(mnemonics, 32, "conv.ovf.u1.un");
			insn_length = 1;
			break;
		case INSN_CONV_OVF_U2_UN:
			strcpy_s(mnemonics, 32, "conv.ovf.u2.un");
			insn_length = 1;
			break;
		case INSN_CONV_OVF_U4_UN:
			strcpy_s(mnemonics, 32, "conv.ovf.u4.un");
			insn_length = 1;
			break;
		case INSN_CONV_OVF_U8_UN:
			strcpy_s(mnemonics, 32, "conv.ovf.u8.un");
			insn_length = 1;
			break;
		case INSN_CONV_OVF_I_UN:
			strcpy_s(mnemonics, 32, "conv.ovf.i.un");
			insn_length = 1;
			break;
		case INSN_CONV_OVF_U_UN:
			strcpy_s(mnemonics, 32, "conv.ovf.u.un");
			insn_length = 1;
			break;
		case INSN_LDC_I4:
		case INSN_LDC_R4:
			// Long branch also works for these instructions, even though they are not a branches.
			insn_length = disasm_long_branch_instruction(next, buffer, remaining, insn, mnemonics);
			break;
		case INSN_LDC_I8:
		case INSN_LDC_R8:
			insn_length = disasm_long_long_instruction(next, buffer, remaining, insn, mnemonics);
			break;
		case INSN_LDC_I4_S:
		case INSN_STLOC_S:
		case INSN_LDLOC_S:
			// Short branch also works for this instruction, even though it is not a branch.
			insn_length = disasm_short_branch_instruction(next, buffer, remaining, insn, mnemonics);
			break;
		case INSN_LDC_I4_0:
			strcpy_s(mnemonics, 32, "ldc.i4.0");
			insn_length = 1;
			break;
		case INSN_LDC_I4_1:
			strcpy_s(mnemonics, 32, "ldc.i4.1");
			insn_length = 1;
			break;
		case INSN_LDC_I4_2:
			strcpy_s(mnemonics, 32, "ldc.i4.2");
			insn_length = 1;
			break;
		case INSN_LDC_I4_3:
			strcpy_s(mnemonics, 32, "ldc.i4.3");
			insn_length = 1;
			break;
		case INSN_LDC_I4_4:
			strcpy_s(mnemonics, 32, "ldc.i4.4");
			insn_length = 1;
			break;
		case INSN_LDC_I4_5:
			strcpy_s(mnemonics, 32, "ldc.i4.5");
			insn_length = 1;
			break;
		case INSN_LDC_I4_6:
			strcpy_s(mnemonics, 32, "ldc.i4.6");
			insn_length = 1;
			break;
		case INSN_LDC_I4_7:
			strcpy_s(mnemonics, 32, "ldc.i4.7");
			insn_length = 1;
			break;
		case INSN_LDC_I4_8:
			strcpy_s(mnemonics, 32, "ldc.i4.8");
			insn_length = 1;
			break;
		case INSN_LDC_I4_M1:
			strcpy_s(mnemonics, 32, "ldc.i4.m1");
			insn_length = 1;
			break;
		case INSN_BR:
		case INSN_BEQ:
		case INSN_BGE:
		case INSN_BGE_UN:
		case INSN_BGT:
		case INSN_BGT_UN:
		case INSN_BLE:
		case INSN_BLE_UN:
		case INSN_BLT:
		case INSN_BLT_UN:
		case INSN_BNE_UN:
		case INSN_BRFALSE:
		case INSN_BRTRUE:
		case INSN_LEAVE:
			insn_length = disasm_long_branch_instruction(next, buffer, remaining, insn, mnemonics);
			break;
		case INSN_BR_S:
		case INSN_BEQ_S:
		case INSN_BGE_S:
		case INSN_BGE_UN_S:
		case INSN_BGT_S:
		case INSN_BGT_UN_S:
		case INSN_BLE_S:
		case INSN_BLE_UN_S:
		case INSN_BLT_S:
		case INSN_BLT_UN_S:
		case INSN_BNE_UN_S:
		case INSN_BRFALSE_S:
		case INSN_BRTRUE_S:
		case INSN_LEAVE_S:
			insn_length = disasm_short_branch_instruction(next, buffer, remaining, insn, mnemonics);
			break;
		case INSN_LDNULL:
			insn_length = 1;
			strcpy_s(mnemonics, "ldnull");
			break;
		case INSN_NOP:
			insn_length = 1;
			strcpy_s(mnemonics, "nop");
			break;
		case INSN_BREAK:
			insn_length = 1;
			strcpy_s(mnemonics, "break");
			break;
		case INSN_NOT:
			insn_length = 1;
			strcpy_s(mnemonics, "not");
			break;
		case INSN_OR:
			insn_length = 1;
			strcpy_s(mnemonics, "or");
			break;
		case INSN_DUP:
			insn_length = 1;
			strcpy_s(mnemonics, 32, "dup");
			break;
		case INSN_POP:
			insn_length = 1;
			strcpy_s(mnemonics, "pop");
			break;
		case INSN_REM:
			insn_length = 1;
			strcpy_s(mnemonics, "rem");
			break;
		case INSN_REM_UN:
			insn_length = 1;
			strcpy_s(mnemonics, "rem.un");
			break;
		case INSN_RET:
			insn_length = 1;
			strcpy_s(mnemonics, "ret");
			break;
		case INSN_SHL:
			insn_length = 1;
			strcpy_s(mnemonics, "shl");
			break;
		case INSN_SHR:
			insn_length = 1;
			strcpy_s(mnemonics, "shr");
			break;
		case INSN_SHR_UN:
			insn_length = 1;
			strcpy_s(mnemonics, "shr.un");
			break;
		case INSN_STLOC_0:
			insn_length = 1;
			strcpy_s(mnemonics, "stloc.0");
			break;
		case INSN_STLOC_1:
			insn_length = 1;
			strcpy_s(mnemonics, "stloc.1");
			break;
		case INSN_STLOC_2:
			insn_length = 1;
			strcpy_s(mnemonics, "stloc.2");
			break;
		case INSN_STLOC_3:
			insn_length = 1;
			strcpy_s(mnemonics, "stloc.3");
			break;
		case INSN_MUL:
			insn_length = 1;
			strcpy_s(mnemonics, "mul");
			break;
		case INSN_MUL_OVF:
			insn_length = 1;
			strcpy_s(mnemonics, "mul.ovf");
			break;
		case INSN_MUL_OVF_UN:
			insn_length = 1;
			strcpy_s(mnemonics, "mul.ovf.un");
			break;
		case INSN_ADD:
			insn_length = 1;
			strcpy_s(mnemonics, "add");
			break;
		case INSN_DIV:
			insn_length = 1;
			strcpy_s(mnemonics, "div");
			break;
		case INSN_DIV_UN:
			insn_length = 1;
			strcpy_s(mnemonics, "div.un");
			break;
		case INSN_NEG:
			insn_length = 1;
			strcpy_s(mnemonics, "neg");
			break;
		case INSN_SUB:
			insn_length = 1;
			strcpy_s(mnemonics, "sub");
			break;
		case INSN_SUB_OVF:
			insn_length = 1;
			strcpy_s(mnemonics, "sub.ovf");
			break;
		case INSN_SUB_OVF_UN:
			insn_length = 1;
			strcpy_s(mnemonics, "sub.ovf.un");
			break;
		case INSN_SWITCH:
			insn_length = disasm_switch_instruction(buffer, remaining, insn, mnemonics);
			break;
		case INSN_XOR:
			insn_length = 1;
			strcpy_s(mnemonics, "xor");
			break;
		case INSN_CALL:
		case INSN_CALLI:
		case INSN_BOX:
		case INSN_UNBOX:
		case INSN_UNBOX_ANY:
		case INSN_CALLVIRT:
		case INSN_CASTCLASS:
		case INSN_CPOBJ:
		case INSN_ISINST:
		case INSN_LDELEM:
		case INSN_LDELEMA:
		case INSN_LDOBJ:
		case INSN_LDSTR:
		case INSN_NEWARR:
		case INSN_NEWOBJ:
		case INSN_REFANYVAL:
		case INSN_LDTOKEN:
		case INSN_STOBJ:
		case INSN_STFLD:
		case INSN_STSFLD:
		case INSN_LDSFLD:
		case INSN_LDSFLD_A:
		case INSN_STELEM:
		case INSN_MKREFANY:
		case INSN_LDFLD:
		case INSN_JMP:
			insn_length = disasm_token_single_instruction(next, buffer, remaining, insn, mnemonics);
			break;
		case INSN_LDLEN:
			insn_length = 1;
			strcpy_s(mnemonics, "ldlen");
			break;
		case INSN_STELEM_I1:
			insn_length = 1;
			strcpy_s(mnemonics, "stelem.i1");
			break;
		case INSN_STELEM_I2:
			insn_length = 1;
			strcpy_s(mnemonics, "stelem.i2");
			break;
		case INSN_STELEM_I4:
			insn_length = 1;
			strcpy_s(mnemonics, "stelem.i4");
			break;
		case INSN_STELEM_I8:
			insn_length = 1;
			strcpy_s(mnemonics, "stelem.i8");
			break;
		case INSN_STELEM_R4:
			insn_length = 1;
			strcpy_s(mnemonics, "stelem.r4");
			break;
		case INSN_STELEM_R8:
			insn_length = 1;
			strcpy_s(mnemonics, "stelem.r8");
			break;
		case INSN_STELEM_I:
			insn_length = 1;
			strcpy_s(mnemonics, "stelem.i");
			break;
		case INSN_STELEM_REF:
			insn_length = 1;
			strcpy_s(mnemonics, "stelem.ref");
			break;
		case INSN_THROW:
			insn_length = 1;
			strcpy_s(mnemonics, "throw");
			break;
		case INSN_LDARG_0:
			insn_length = 1;
			strcpy_s(mnemonics, "ldarg.0");
			break;
		case INSN_LDARG_1:
			insn_length = 1;
			strcpy_s(mnemonics, "ldarg.1");
			break;
		case INSN_LDARG_2:
			insn_length = 1;
			strcpy_s(mnemonics, "ldarg.2");
			break;
		case INSN_LDARG_3:
			insn_length = 1;
			strcpy_s(mnemonics, "ldarg.3");
			break;
		case INSN_STIND_I1:
		case INSN_STIND_I2:
		case INSN_STIND_I4:
		case INSN_STIND_I8:
		case INSN_STIND_R4:
		case INSN_STIND_R8:
		case INSN_STIND_I:
		case INSN_STIND_REF:
			insn_length = disasm_stind_instruction(buffer, remaining, mnemonics);
			break;
		case INSN_LDLOC_0:
			insn_length = 1;
			strcpy_s(mnemonics, "ldloc.0");
			break;
		case INSN_LDLOC_1:
			insn_length = 1;
			strcpy_s(mnemonics, "ldloc.1");
			break;
		case INSN_LDLOC_2:
			insn_length = 1;
			strcpy_s(mnemonics, "ldloc.2");
			break;
		case INSN_LDLOC_3:
			insn_length = 1;
			strcpy_s(mnemonics, "ldloc.3");
			break;
		case INSN_LDARG_S:
			if (remaining < 2) return 0;
			insn_length = 2;
			strcpy_s(mnemonics, "ladarg.s");
			insn.operand = buffer[1];
			insn.operand_length = sizeof(uint8_t);
			break;
		case INSN_STARG_S:
			if (remaining < 2) return 0;
			insn_length = 2;
			strcpy_s(mnemonics, "starg.s");
			insn.operand = buffer[1];
			insn.operand_length = sizeof(uint8_t);
			break;
		case INSN_ENDFINALLY:
			strcpy_s(mnemonics, "endfinally");
			insn_length = 1;
			break;
		case INSN_LDIND_I1:
			strcpy_s(mnemonics, "ldind.i1");
			insn_length = 1;
			break;
		case INSN_LDIND_I2:
			strcpy_s(mnemonics, "ldind.i2");
			insn_length = 1;
			break;
		case INSN_LDIND_I4:
			strcpy_s(mnemonics, "ldind.i4");
			insn_length = 1;
			break;
		case INSN_LDIND_I8:
			strcpy_s(mnemonics, "ldind.i8");
			insn_length = 1;
			break;
		case INSN_LDIND_U1:
			strcpy_s(mnemonics, "ldind.u1");
			insn_length = 1;
			break;
		case INSN_LDIND_U2:
			strcpy_s(mnemonics, "ldind.u2");
			insn_length = 1;
			break;
		case INSN_LDIND_U4:
			strcpy_s(mnemonics, "ldind.u4");
			insn_length = 1;
			break;
		case INSN_LDIND_R4:
			strcpy_s(mnemonics, "ldind.r4");
			insn_length = 1;
			break;
		case INSN_LDIND_R8:
			strcpy_s(mnemonics, "ldind.r8");
			insn_length = 1;
			break;
		case INSN_LDIND_I:
			strcpy_s(mnemonics, "ldind.i");
			insn_length = 1;
			break;
		case INSN_LDIND_REF:
			strcpy_s(mnemonics, "ldind.ref");
			insn_length = 1;
			break;
		default: return 0;
		}

		insn.num_opcode_bytes = 1;
	}

	// Still here, so the instruction is valid.
	insn.insn_length = insn_length;
	strcpy_s(insn.mnemonics, mnemonics);

	// Still here, so no error occurred.
	memcpy(insn.opcodes, buffer, insn.num_opcode_bytes);
	return insn_length;
}