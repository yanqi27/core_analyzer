/*
 * decode.h
 *
 *  Created on: Aug 22, 2014
 *      Author: myan
 */
#ifndef DECODE_H_
#define DECODE_H_

#include "x_dep.h"
#include "x_type.h"
#include "opcode/i386.h"

/*
 *  types for decode function
 */

// Register index
#define RAX 0
#define RCX 1
#define RDX 2
#define RBX 3
#define RSP 4
#define RBP 5
#define RSI 6
#define RDI 7
#define R8  8
#define R9  9
#define R10 10
#define R11 11
#define R12 12
#define R13 13
#define R14 14
#define R15 15
#define RIP 16
#define RXMM0 17
#define RXMM1 18
#define RXMM2 19
#define RXMM3 20
#define RXMM4 21
#define RXMM5 22
#define RXMM6 23
#define RXMM7 24
#define RXMM8 25
#define RXMM9 26
#define RXMM10 27
#define RXMM11 28
#define RXMM12 29
#define RXMM13 30
#define RXMM14 31
#define RXMM15 32
#define TOTAL_REGS 33

/*
 * structure for an instruction operand
 */
enum ca_operand_type {
	CA_OP_UNSET,
	CA_OP_REGISTER,
	CA_OP_IMMEDIATE,
	CA_OP_MEMORY,
};

struct ca_op_register {
	const char* name;
	int size;
	int index;
};

struct ca_op_immediate {
	bfd_vma immediate;
};

struct ca_op_memory {
	struct ca_op_register  base_reg;
	struct ca_op_register  index_reg;
	struct ca_op_immediate disp;
	int scale;
};

struct ca_operand {
	enum ca_operand_type type;
	union {
		struct ca_op_register  reg;
		struct ca_op_immediate immed;
		struct ca_op_memory    mem;
	};
};

/*
 * Structure to record a disassembled instruction
 */
#define MAX_OPCODE_NAME_SZ 8
struct ca_dis_insn
{
	// instruction address
	CORE_ADDR pc;
	// disassembled text
	char* dis_string;
	// opcode name
	char opcode_name[MAX_OPCODE_NAME_SZ];
	// operands
	struct ca_operand operands[MAX_OPERANDS];
	int op_size;
	int num_operand;
	// the following members are set with help of current context
	CORE_ADDR branch_pc;		// destination address of a branch instruction
	unsigned int annotate:1;	// this instruction is suitable for annotation
	unsigned int branch:1;		// branch instruction
	unsigned int call:1;		// call instruction
	unsigned int lea:1;			// lea instruction
	unsigned int push:1;		// push instruction
	unsigned int jmp:1;			// jmp instruction
	unsigned int jmp_target:1;	// current instruction is the target of another jmp instruciton
	unsigned int reserved:26;
};

/*
 * Register value/symbol/type at certain "pc"
 */
struct ca_reg_value
{
	// instruction address at which the value is set
	CORE_ADDR pc;
	char* sym_name;
	struct type* type;
	size_t value;
	// flags
	unsigned int has_value:1;
	unsigned int vptr:1;		// _vptr, i.e. pointer to "vtable for class T"
	unsigned int reserved:30;
};
#define REG_KNOWN(reg)  ((reg)->has_value || (reg)->sym_name || (reg)->type)

/*
 * Values of a register at various (ascending) instruction addresses
 * 	[0] is for the initial value, e.g. input parameters
 * 	[1], [2], .., are values/symbols/types when the register is changed
 */
struct ca_reg_vector
{
	struct ca_reg_value* start;
	struct ca_reg_value* finish;
	struct ca_reg_value* end_of_storage;
};

#define REG_SET_SZ sizeof(struct ca_reg_value [TOTAL_REGS])

/*
 * A table of all registers interested
 */
struct ca_reg_table
{
	struct ca_reg_vector vecs[TOTAL_REGS];		// vector of each register expands as it changes
	struct ca_reg_value* cur_regs[TOTAL_REGS];	// pointers to registers at current "pc"
};

/*
 * Context of a decoded function
 */
struct decode_control_block
{
	struct gdbarch* gdbarch;
	struct ui_out*  uiout;
	struct disassemble_info* di;
	CORE_ADDR low;						// User picked instruction range [low, hight]
	CORE_ADDR high;
	CORE_ADDR current;					// Instruction being executed, i.e. "call" if not innermost frame
	CORE_ADDR func_start;				// Function range [start, end]
	CORE_ADDR func_end;
	struct ca_dis_insn* insn;
	struct ca_reg_value* param_regs;	// parameters known at the function entry
	struct ca_reg_value* user_regs;		// user-inputed register values
	unsigned int verbose:1;
	unsigned int innermost_frame:1;
	unsigned int reserved:30;
};

extern void decode_func(char *arg);

extern int decode_insns(struct decode_control_block*);

extern int ca_print_insn_i386(bfd_vma pc, struct decode_control_block*);

#endif // DECODE_H_
