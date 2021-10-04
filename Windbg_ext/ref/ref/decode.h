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

#ifdef _WIN32

#define CORE_ADDR address_t
#define bfd_vma ULONG64
#define bfd_signed_vma LONG64

#ifndef OPCODE_I386_H
#define OPCODE_I386_H

#ifndef SYSV386_COMPAT
/* Set non-zero for broken, compatible instructions.  Set to zero for
   non-broken opcodes at your peril.  gcc generates SystemV/386
   compatible instructions.  */
#define SYSV386_COMPAT 1
#endif

#define MOV_AX_DISP32 0xa0
#define POP_SEG_SHORT 0x07
#define JUMP_PC_RELATIVE 0xeb
#define INT_OPCODE  0xcd
#define INT3_OPCODE 0xcc
/* The opcode for the fwait instruction, which disassembler treats as a
   prefix when it can.  */
#define FWAIT_OPCODE 0x9b

/* Instruction prefixes.
   NOTE: For certain SSE* instructions, 0x66,0xf2,0xf3 are treated as
   part of the opcode.  Other prefixes may still appear between them
   and the 0x0f part of the opcode.  */
#define ADDR_PREFIX_OPCODE 0x67
#define DATA_PREFIX_OPCODE 0x66
#define LOCK_PREFIX_OPCODE 0xf0
#define CS_PREFIX_OPCODE 0x2e
#define DS_PREFIX_OPCODE 0x3e
#define ES_PREFIX_OPCODE 0x26
#define FS_PREFIX_OPCODE 0x64
#define GS_PREFIX_OPCODE 0x65
#define SS_PREFIX_OPCODE 0x36
#define REPNE_PREFIX_OPCODE 0xf2
#define REPE_PREFIX_OPCODE  0xf3
#define XACQUIRE_PREFIX_OPCODE 0xf2
#define XRELEASE_PREFIX_OPCODE 0xf3

#define TWO_BYTE_OPCODE_ESCAPE 0x0f
#define NOP_OPCODE (char) 0x90

/* register numbers */
#define EAX_REG_NUM 0
#define ECX_REG_NUM 1
#define EDX_REG_NUM 2
#define EBX_REG_NUM 3
#define ESP_REG_NUM 4
#define EBP_REG_NUM 5
#define ESI_REG_NUM 6
#define EDI_REG_NUM 7

/* modrm_byte.regmem for twobyte escape */
#define ESCAPE_TO_TWO_BYTE_ADDRESSING ESP_REG_NUM
/* index_base_byte.index for no index register addressing */
#define NO_INDEX_REGISTER ESP_REG_NUM
/* index_base_byte.base for no base register addressing */
#define NO_BASE_REGISTER EBP_REG_NUM
#define NO_BASE_REGISTER_16 6

/* modrm.mode = REGMEM_FIELD_HAS_REG when a register is in there */
#define REGMEM_FIELD_HAS_REG 0x3/* always = 0x3 */
#define REGMEM_FIELD_HAS_MEM (~REGMEM_FIELD_HAS_REG)

/* Extract fields from the mod/rm byte.  */
#define MODRM_MOD_FIELD(modrm) (((modrm) >> 6) & 3)
#define MODRM_REG_FIELD(modrm) (((modrm) >> 3) & 7)
#define MODRM_RM_FIELD(modrm)  (((modrm) >> 0) & 7)

/* Extract fields from the sib byte.  */
#define SIB_SCALE_FIELD(sib) (((sib) >> 6) & 3)
#define SIB_INDEX_FIELD(sib) (((sib) >> 3) & 7)
#define SIB_BASE_FIELD(sib)  (((sib) >> 0) & 7)

/* x86-64 extension prefix.  */
#define REX_OPCODE	0x40

/* Non-zero if OPCODE is the rex prefix.  */
#define REX_PREFIX_P(opcode) (((opcode) & 0xf0) == REX_OPCODE)

/* Indicates 64 bit operand size.  */
#define REX_W	8
/* High extension to reg field of modrm byte.  */
#define REX_R	4
/* High extension to SIB index field.  */
#define REX_X	2
/* High extension to base field of modrm or SIB, or reg field of opcode.  */
#define REX_B	1

/* max operands per insn */
#define MAX_OPERANDS 5

/* max immediates per insn (lcall, ljmp, insertq, extrq) */
#define MAX_IMMEDIATE_OPERANDS 2

/* max memory refs per insn (string ops) */
#define MAX_MEMORY_OPERANDS 2

/* max size of insn mnemonics.  */
#define MAX_MNEM_SIZE 20

/* max size of register name in insn mnemonics.  */
#define MAX_REG_NAME_SIZE 8

#endif /* OPCODE_I386_H */

typedef int (*fprintf_ftype) (void *, const char*, ...);

typedef struct disassemble_info
{
	fprintf_ftype fprintf_func;
	void *stream;
	//void *application_data;
	//enum bfd_flavour flavour;
	//enum bfd_architecture arch;
	//unsigned long mach;
	//enum bfd_endian endian;
	//enum bfd_endian endian_code;
	//void *insn_sets;
	//asection *section;
	//asymbol **symbols;
	//int num_symbols;

	//asymbol **symtab;
	//int symtab_pos;
	//int symtab_size;

	//unsigned long flags;
	//#define INSN_HAS_RELOC	 (1 << 31)
	//#define DISASSEMBLE_DATA (1 << 30)
	//#define USER_SPECIFIED_MACHINE_TYPE (1 << 29)

	void *private_data;

	int (*read_memory_func)
		(ULONG64 memaddr, unsigned char *myaddr, unsigned int length,
		struct disassemble_info *dinfo);

	void (*memory_error_func)
		(int status, ULONG64 memaddr, struct disassemble_info *dinfo);

	void (*print_address_func)
		(ULONG64 addr, struct disassemble_info *dinfo);

	//int (* symbol_at_address_func)
	//	(ULONG64 addr, struct disassemble_info *dinfo);

	//bfd_boolean (* symbol_is_valid)
	//	(asymbol *, struct disassemble_info *dinfo);

	//unsigned char *buffer;
	//ULONG64 buffer_vma;
	//unsigned int buffer_length;

	int bytes_per_line;

	//int bytes_per_chunk;
	//enum bfd_endian display_endian;

	//unsigned int octets_per_byte;

	//unsigned int skip_zeroes;

	//unsigned int skip_zeroes_at_end;

	//bfd_boolean disassembler_needs_relocs;

	//char insn_info_valid;
	//char branch_delay_insns;
	//char data_size;
	//enum dis_insn_type insn_type;
	//ULONG64 target;
	//ULONG64 target2;

	char * disassembler_options;
} disassemble_info;

#endif // _WIN32

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
	struct win_type type;
	size_t value;
	// flags
	unsigned int has_value:1;
	unsigned int vptr:1;		// _vptr, i.e. pointer to "vtable for class T"
	unsigned int reserved:30;
};
#define REG_KNOWN(reg)  ((reg)->has_value || (reg)->sym_name || (reg)->type.mod_base)

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
