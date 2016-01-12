/*
 * decode.c
 *
 *  Created on: Aug 22, 2014
 *      Author: myan
 */
#include "decode.h"
#include "dis-asm.h"
#include "search.h"
#include "segment.h"

enum CA_OPERATOR
{
	ADD,
	SUBTRACT,
	MULTIPLY,
	DIVIDE,
	INCREMENT,
	DECREMENT,
	BITWISE_AND,
	BITWISE_OR,
	BITWISE_NOT,
	BITWISE_XOR,
	BITWISE_SHIFT_RIGHT,
	BITWISE_SHIFT_LEFT,
	ROTATE_RIGHT,
	ROTATE_LEFT
};

// A local variable on stack, its value can always be queried given its address
struct ca_stack_var
{
	address_t stack_addr;
	char* sym_name;
	struct type* type;
};

/*
 * Globals
 */
// register table
#define INIT_REG_ARRAY_SZ 32
static struct ca_reg_table g_reg_table;

// stack variables
#define STACK_ARRAY_INIT_CAP 32
static struct ca_stack_var* g_stack_vars = NULL;
static unsigned int g_num_stack_vars = 0;
static unsigned int g_stack_vars_capacity = 0;

// disassembled instructions
#define INSN_BUFFER_INIT_CAP 32
static struct ca_dis_insn* g_insns_buffer = NULL;
static unsigned int g_insns_buffer_capacity = 0;
static unsigned int g_num_insns = 0;

/*
 * Forward functions
 */
static int dump_insns(struct decode_control_block* decode_cb);

// Instruction array
static void init_dis_insn_buffer(void);
static struct ca_dis_insn* get_new_dis_insn(void);
static void process_one_insn(struct ca_dis_insn* insn, int current);
static void process_mov_insn(struct ca_dis_insn* insn,
								struct ca_operand* dst_op,
								struct ca_operand* src_op);
static void process_binary_op_insn(struct ca_dis_insn* insn,
									struct ca_operand* dst_op,
									struct ca_operand* src_op,
									enum CA_OPERATOR op);
static void process_unary_op_insn(struct ca_dis_insn* insn,
									struct ca_operand* dst_op, enum CA_OPERATOR op);
static void print_one_insn(struct ca_dis_insn* insn, struct ui_out* uiout);

// Instruction Operand
static void print_one_operand(struct ui_out* uiout, struct ca_operand* op, size_t op_size);
static int known_op_value(struct ca_operand* op);
static bfd_vma get_address(struct ca_operand* op);
static size_t get_op_value(struct ca_operand* op, size_t op_size);
static void set_op_value(struct ca_operand* op, size_t val, CORE_ADDR pc);
static void set_op_unknown(struct ca_operand* op, CORE_ADDR pc);
static void get_op_symbol_type(struct ca_operand* op, int lea,
							char** psymname, struct type** ptype, int* pvptr);
static void set_dst_op(struct ca_dis_insn* insn, struct ca_operand* dst_op,
		int has_value, size_t val, char* symname, struct type* type, int is_vptr);
static size_t bit_rotate(size_t val, size_t nbits, enum CA_OPERATOR dir, int size);
static int is_stack_address(struct ca_operand* op);
static void set_op_value_symbol_type(struct ca_dis_insn* insn,
								struct ca_operand* sym_op, struct ca_operand* dst_op,
								int has_value, size_t val);

// Register table
static void init_reg_table(struct ca_reg_value* regs);
static void reset_reg_table(void);
static void validate_reg_table(void);
static void set_reg_table_at_pc(struct ca_reg_value* src, CORE_ADDR pc);
static void set_current_reg_pointers(struct ca_dis_insn* insn);
static void adjust_table_after_absolute_branch(CORE_ADDR pc);
static struct ca_reg_value* get_new_reg(unsigned int reg_idx);
static struct ca_reg_value* get_reg_at_pc(unsigned int reg_idx, CORE_ADDR pc);
static void set_reg_unknown_at_pc(unsigned int reg_idx, CORE_ADDR pc);
static void set_reg_value_at_pc(unsigned int reg_idx, size_t val, CORE_ADDR pc);
static void set_cur_reg_value(unsigned int reg_idx, size_t val);

// Stack values
static void init_stack_vars(void);
static void reset_stack_vars(void);
static struct ca_stack_var* get_new_stack_var(address_t saddr);
static struct ca_stack_var* get_stack_var(address_t saddr);
static void set_stack_sym_type(char* sym_name, struct type* type, address_t saddr);

// Misc
static int is_same_string(const char* str1, const char* str2);

/*
 * First, disassemble all instructions of the function and store them in buffer
 * Second, follow and calculate register values at each instruction
 * Finally, display all disassembled instruction with annotation of object context
 */
int decode_insns(struct decode_control_block* decode_cb)
{
	unsigned int insn_index, i;
	int num_insns = 0;
	struct ui_out *uiout = decode_cb->uiout;

	// Disassemble the whole function even if user chooses
	// only a subset of it
	num_insns += dump_insns(decode_cb);

	// copy known function parameters
	init_reg_table(decode_cb->param_regs);
	init_stack_vars();

	g_reg_table.cur_regs[RIP]->has_value = 1;
	// Annotate the context of each instruction
	for (insn_index = 0; insn_index < g_num_insns; insn_index++)
	{
		int cur_insn = 0;
		struct ca_dis_insn* insn = &g_insns_buffer[insn_index];

		// update program counter for RIP-relative instruction
		// RIP points to the address of the next instruction before executing current one
		if (insn_index + 1 < g_num_insns)
			set_reg_value_at_pc(RIP, (insn+1)->pc, insn->pc);

		// user may set some register values deliberately
		if (decode_cb->user_regs)
		{
			if (insn->pc == decode_cb->low
				|| (insn_index + 1 < g_num_insns && g_insns_buffer[insn_index + 1].pc > decode_cb->low) )
			{
				if (insn->pc == decode_cb->func_start)
					set_reg_table_at_pc(decode_cb->user_regs, 0);
				else
					set_reg_table_at_pc(decode_cb->user_regs, insn->pc);
			}
		}

		// analyze and update register context affected by this instruction
		if (decode_cb->innermost_frame)
		{
			if (insn->pc == decode_cb->current)
				cur_insn = 1;
		}
		else if (insn_index + 1 < g_num_insns && g_insns_buffer[insn_index + 1].pc == decode_cb->current)
			cur_insn = 1;

		process_one_insn(insn, cur_insn);

		if (cur_insn)
		{
			// return the register context back to caller
			for (i = 0; i < TOTAL_REGS; i++)
			{
				struct ca_reg_value* reg = g_reg_table.cur_regs[i];
				if (reg->has_value)
				{
					// only pass on values, symbol may be out of context in another function
					struct ca_reg_value* dst = &decode_cb->param_regs[i];
					memcpy(dst, reg, sizeof(struct ca_reg_value));
					dst->sym_name = NULL;
				}
			}
		}
	}
	if (decode_cb->verbose)
		validate_reg_table();

	// display disassembled insns
	for (insn_index = 0; insn_index < g_num_insns; insn_index++)
	{
		struct ca_dis_insn* insn = &g_insns_buffer[insn_index];
		// parts of the symbolic representation of the address
		int unmapped;
		int offset;
		int line;
		char *filename = NULL;
		char *name = NULL;

		if (insn->pc >= decode_cb->high)
			break;
		else if (insn->pc >= decode_cb->low)
		{
			// instruction address + offset
			ui_out_field_core_addr(uiout, "address", insn->pc);

			if (!build_address_symbolic(insn->pc, 0, &name, &offset, &filename,
					&line, &unmapped))
			{
				ui_out_text(uiout, " <");
				//if (decode_cb->verbose)
				//	ui_out_field_string(uiout, "func-name", name);
				ui_out_text(uiout, "+");
				ui_out_field_int(uiout, "offset", offset);
				ui_out_text(uiout, ">:\t");
			} else
				ui_out_text(uiout, ":\t");

			// disassembled instruction with annotation
			print_one_insn(insn, uiout);

			if (filename != NULL)
				xfree(filename);
			if (name != NULL)
				xfree(name);
		}
	}

	reset_reg_table();
	reset_stack_vars();

	return num_insns;
}

#define MAX_SPACING 31
/*
 * Display a disassembled instruction with annotation
 */
static void print_one_insn(struct ca_dis_insn* insn, struct ui_out* uiout)
{
	int pos;
	struct ca_operand* dst_op;

	ui_out_text(uiout, insn->dis_string);

	pos = strlen(insn->dis_string);
	if (pos < MAX_SPACING)
		ui_out_spaces(uiout, MAX_SPACING - pos);
	ui_out_text(uiout, " ## ");

	if (insn->num_operand == 0)
	{
		ui_out_text(uiout, "\n");
		return;
	}

	// special case
	/*if (insn->call)
	{
		// reminder that $rax is set to return value after a "call" instruction
		// if the called function has an integer return value
		// (unfortunately return type is not known for a function)
		ui_out_text(uiout, "(%rax=? on return) ");
	}*/

	dst_op = &insn->operands[0];
	// annotation of object context
	if (insn->annotate)
	{
		size_t ptr_sz = g_ptr_bit >> 3;
		int has_value = 0;
		size_t val = 0xcdcdcdcd;
		int op_size = insn->op_size;
		const char* symname = NULL;
		struct type* type   = NULL;
		int is_vptr         = 0;
		char* name_to_free = NULL;

		// update register context by "pc"
		set_current_reg_pointers(insn);

		// Get the instruction's destination value/symbol/type
		if (dst_op->type == CA_OP_MEMORY)
		{
			// if the destination is a known local variable
			if (is_stack_address(dst_op))
			{
				address_t addr = get_address(dst_op);
				struct ca_stack_var* sval = get_stack_var(addr);
				if (sval)
				{
					symname = sval->sym_name;
					type = sval->type;
				}
				else
				{
					struct symbol* sym;
					struct object_reference aref;
					memset(&aref, 0, sizeof(aref));
					aref.vaddr = addr;
					aref.value = 0;
					aref.target_index = -1;
					sym = get_stack_sym(&aref, NULL, NULL);
					if (sym)
					{
						symname = SYMBOL_PRINT_NAME (sym);
						type = SYMBOL_TYPE(sym);
					}
				}
			}
			// could it be a known heap object
			if (!symname && !type)
			{
				// this function will allocate buffer for the symbol name if any, remember to free it
				get_op_symbol_type(dst_op, 0, &name_to_free, &type, NULL);
				symname = name_to_free;
			}
			// Since flag insn->annotate is set, dst_op's value should be calculated
			val = get_op_value(dst_op, op_size);
			has_value = 1;
		}
		else if (dst_op->type == CA_OP_REGISTER)
		{
			struct ca_reg_value* dst_reg = get_reg_at_pc(dst_op->reg.index, insn->pc);
			if (dst_reg)
			{
				symname = dst_reg->sym_name;
				type    = dst_reg->type;
				is_vptr = dst_reg->vptr;
				if (dst_reg->has_value)
				{
					has_value = 1;
					val = dst_reg->value;
				}
			}
		}

		// Name and value (if known) of destination
		print_one_operand(uiout, dst_op, op_size);
		if (has_value)
			ui_out_message(uiout, 0, "=0x%lx", val);
		else
			ui_out_text(uiout, "=?");

		// Symbol or type of destination
		if (dst_op->type == CA_OP_REGISTER
			&& dst_op->reg.index == RSP)
		{
			if (val == g_debug_context.sp)
				ui_out_text(uiout, " End of function prologue");
			ui_out_text(uiout, "\n");
		}
		else
		{
			// symbol or type is known
			if (symname || type)
			{
				ui_out_text(uiout, "(");
				if (symname)
				{
					ui_out_message(uiout, 0, "symbol=\"%s\"", symname);
				}
				if (type)
				{
					CHECK_TYPEDEF(type);
					if (symname)
						ui_out_text(uiout, " ");
					ui_out_text(uiout, "type=\"");
					if (is_vptr)
					{
						const char * type_name = type_name_no_tag(type);
						if (type_name)
							ui_out_message(uiout, 0, "vtable for %s", type_name);
						else
						{
							ui_out_text(uiout, "vtable for ");
							print_type_name (type, NULL, NULL, NULL);
						}
					}
					else
						print_type_name (type, NULL, NULL, NULL);
					ui_out_text(uiout, "\"");
				}
				ui_out_text(uiout, ")\n");
			}
			// whatever we can get form the value
			else
			{
				address_t location = 0;
				int offset = 0;

				//if (insn->num_operand > 1)
				//{
				//	struct ca_operand* src_op = &insn->operands[1];
				//	get_location(src_op, &location, &offset);
				//}

				print_op_value_context (val,
						op_size > 0 ? op_size : ptr_sz,
						location, offset, insn->lea);
			}
		}
		if (name_to_free)
			free (name_to_free);
	}
	else
	{
		if (dst_op->type == CA_OP_REGISTER)
		{
			struct ca_reg_value* dst_reg = get_reg_at_pc(dst_op->reg.index, insn->pc);
			// The destination register is changed from known to unknown state at this instruction
			if (dst_reg)
				ui_out_message(uiout, 0, "%s=?", dst_op->reg.name);
		}
		ui_out_text(uiout, "\n");
	}
}

/*
 *  The key function to discover an instruction's object context
 */
static void process_one_insn(struct ca_dis_insn* insn, int current)
{
	size_t ptr_sz = g_ptr_bit >> 3;
	size_t val;
	int op_size = insn->op_size;
	size_t mask = (size_t)(-1);
	struct ca_operand* dst_op = NULL;
	struct ca_operand* src_op = NULL;

	if (*insn->opcode_name == 0)
		return;

	if (op_size > 0)
		mask = mask >> ((8 - op_size) * 8);

	// this instruction is the target of a previous "jmp" instruction
	if (insn->jmp_target)
		adjust_table_after_absolute_branch(insn->pc);

	// 1st operand(insn->operands[0]) is the destination
	// (and possibly source) in most cases
	dst_op = &insn->operands[0];
	src_op = &insn->operands[1];

	// Switch on op_code
	// roughly in the order of most popular to least likely
	if (strncmp(insn->opcode_name, "mov", 3) == 0
			|| strncmp(insn->opcode_name, "cvt", 3) == 0)
	{
		//   "movd"  move doubleword or quadword
		//   "movnti" move non-temporal doubleword or quadword
		//   "movs" "movs[b/w/d/q] move string
		//   "movsx" move with sign-extension
		//   "movsxd" move with sign-extend doubleword
		//   "movzx" move with zero-extension
		process_mov_insn(insn, dst_op, src_op);
	}
	/*else if (strncmp(insn->opcode_name, "test", 4) == 0)
	{
		if (insn->operands[0].type == CA_OP_REGISTER && insn->operands[1].type == CA_OP_REGISTER
			&& insn->operands[0].reg.index == insn->operands[1].reg.index)
		{
			// test zero
			//print_one_operand(&insn->operands[1], uiout, CA_TRUE);
			//ui_out_text(uiout, "==0");
		}
		else if (known_op_value(&insn->operands[1]) && known_op_value(&insn->operands[0]))
		{
			//print_one_operand(&insn->operands[1], uiout, CA_TRUE);
			//ui_out_text(uiout, "==");
			//print_one_operand(&insn->operands[0], uiout, CA_TRUE);
		}
	}
	else if (strncmp(insn->opcode_name, "cmp", 3) == 0)
	{
		if (known_op_value(&insn->operands[1]) && known_op_value(&insn->operands[0]))
		{
			//print_one_operand(&insn->operands[1], uiout, CA_TRUE);
			//ui_out_text(uiout, "<=>");
			//print_one_operand(&insn->operands[0], uiout, CA_TRUE);
		}
	}
	else if (strncmp(insn->opcode_name, "leave", 5) == 0)
	{
		// this has to be before "lea" instr to avoid ambiguity
		// it is equivelent to two instruction
		//     mov rbp, rsp
		//     pop rbp
	}*/
	else if (strncmp(insn->opcode_name, "lea", 3) == 0)
	{
		// load effective address
		// source must be memory and destination must be register
		insn->lea = 1;
		process_mov_insn(insn, dst_op, src_op);
	}
	else if (strncmp(insn->opcode_name, "call", 4) == 0)
	{
		insn->call = 1;
		if (dst_op->type != CA_OP_IMMEDIATE && known_op_value(dst_op))
		{
			insn->annotate = 1;
			if (dst_op->type == CA_OP_REGISTER)
				set_reg_value_at_pc(dst_op->reg.index, g_reg_table.cur_regs[dst_op->reg.index]->value, insn->pc);
		}
		if (!current)
		{
			// rax is used for return value most of the time
			set_reg_unknown_at_pc(RAX, insn->pc+1);
			// when the function returns, all volatile registers may have been changed
			//
			// In a second thought, even if the called function does change a volatile register,
			// the code after the "call" should reload it before using it.
			// The code following "call" instruction could be the destination of branch/jmp instruction,
			// which skips "call". If we set all volatile registers unknown, we will lose them in that case.
			set_reg_unknown_at_pc(RCX, insn->pc+1);
			set_reg_unknown_at_pc(RDX, insn->pc+1);
			set_reg_unknown_at_pc(RSI, insn->pc+1);
			set_reg_unknown_at_pc(RDI, insn->pc+1);
			set_reg_unknown_at_pc(R8, insn->pc+1);
			set_reg_unknown_at_pc(R9, insn->pc+1);
			set_reg_unknown_at_pc(R10, insn->pc+1);
			set_reg_unknown_at_pc(R11, insn->pc+1);
		}
	}
	else if (strncmp(insn->opcode_name, "jmp", 3) == 0)
	{
		// Non-conditional branch, need to adjust register context
		insn->jmp = 1;
		if (known_op_value(dst_op))
		{
			insn->branch_pc = get_op_value(dst_op, op_size);
			if (insn->branch_pc < insn->pc)
			{
				// Get previous register context if jmp back
				adjust_table_after_absolute_branch(insn->pc);
			}
			else
			{
				// Prepare for the target-addressed instruction if jmp forward
				struct ca_dis_insn* last_insn = &g_insns_buffer[g_num_insns];
				struct ca_dis_insn* cursor = insn + 1;
				while (cursor < last_insn)
				{
					if (cursor->pc == insn->branch_pc)
					{
						cursor->jmp_target = 1;
						break;
					}
					cursor++;
				}
				if (cursor == last_insn)	// jmp target is not within current function
					adjust_table_after_absolute_branch(insn->pc);
			}
		}
		else
			adjust_table_after_absolute_branch(insn->pc);
	}
	else if (insn->opcode_name[0] == 'j' &&
			(insn->opcode_name[1] == 'e'
				|| (insn->opcode_name[1] == 'n' && insn->opcode_name[2] == 'e')
				|| insn->opcode_name[1] == 'a'
				|| insn->opcode_name[1] == 'b'
				|| insn->opcode_name[1] == 's'
				|| (insn->opcode_name[1] == 'n' && insn->opcode_name[2] == 's')
				|| insn->opcode_name[1] == 'p'
				|| (insn->opcode_name[1] == 'n' && insn->opcode_name[2] == 'p')
				|| insn->opcode_name[1] == 'l'
				|| (insn->opcode_name[1] == 'l' && insn->opcode_name[2] == 'e')
				|| insn->opcode_name[1] == 'g'
				|| insn->opcode_name[1] == 'o'
				|| (insn->opcode_name[1] == 'n' && insn->opcode_name[2] == 'o') ) )
	{
		// Branch instructions
		// "je", "jne", "ja", "jb", "js", "jns", "jp", "jnp", "jl", "jle",
		// "jg", "jo", "jno"
		insn->branch = 1;
		if (known_op_value(dst_op))
			insn->branch_pc = get_op_value(dst_op, op_size);
	}
	else if (strncmp(insn->opcode_name, "push", 4) == 0)
	{
		// "push" is equivalent to "sub 8, %rsp" and "mov src, (%rsp)"
		// update RSP value
		size_t rsp = g_reg_table.cur_regs[RSP]->value - ptr_sz;
		set_reg_value_at_pc(RSP, rsp, insn->pc);

		insn->num_operand = 2;
		insn->push = 1;
		memcpy(src_op, dst_op, sizeof(struct ca_operand));	// dst_op(operand[0]) is actually src
		dst_op->type = CA_OP_MEMORY;
		dst_op->mem.base_reg.index = RSP;
		dst_op->mem.base_reg.name = "%rsp";
		dst_op->mem.base_reg.size = ptr_sz;
		dst_op->mem.disp.immediate = 0;
		dst_op->mem.index_reg.name = NULL;
		dst_op->mem.scale = 0;
		process_mov_insn(insn, dst_op, src_op);

		insn->annotate = 1;
	}
	else if (strncmp(insn->opcode_name, "pop", 3) == 0)
	{
		// "pop" is equivalent to "mov (%rsp), dst" and "add 8, %rsp"
		size_t rsp = g_reg_table.cur_regs[RSP]->value;

		insn->num_operand = 2;
		src_op->type = CA_OP_MEMORY;
		src_op->mem.base_reg.index = RSP;
		src_op->mem.base_reg.name = "%rsp";
		src_op->mem.base_reg.size = ptr_sz;
		src_op->mem.disp.immediate = 0;
		src_op->mem.index_reg.name = NULL;
		src_op->mem.scale = 0;
		process_mov_insn(insn, dst_op, src_op);

		// update RSP value
		set_reg_value_at_pc(RSP, rsp +  ptr_sz, insn->pc);
		insn->annotate = 1;
	}
	else if (strncmp(insn->opcode_name, "cmov", 4) == 0)
	{
		// conditional move
		set_op_unknown(dst_op, insn->pc);
	}
	else if (strncmp(insn->opcode_name, "add", 3) == 0
			|| strncmp(insn->opcode_name, "adc", 3) == 0)
	{
		process_binary_op_insn(insn, dst_op, src_op, ADD);
	}
	else if (strncmp(insn->opcode_name, "sub", 3) == 0
			|| strncmp(insn->opcode_name, "sbb", 3) == 0)
	{
		if (dst_op->type == CA_OP_REGISTER && src_op->type == CA_OP_REGISTER
				&& dst_op->reg.index == src_op->reg.index)
		{
			insn->annotate = 1;
			val = 0;
			set_op_value(dst_op, 0, insn->pc);
		}
		else
			process_binary_op_insn(insn, dst_op, src_op, SUBTRACT);
	}
	else if (strncmp(insn->opcode_name, "imul", 4) == 0)
	{
		// two operands multiplication
		if (insn->num_operand == 2)
		{
			process_binary_op_insn(insn, dst_op, src_op, MULTIPLY);
		}
		else
		{
			if (insn->num_operand == 3 && known_op_value(&insn->operands[1]) && known_op_value(&insn->operands[2]))
			{
				insn->annotate = 1;
				val = get_op_value(&insn->operands[1], op_size) * get_op_value(&insn->operands[2], op_size);
				val &= mask;
				set_op_value(dst_op, val, insn->pc);
			}
			else if (insn->num_operand == 1 && known_op_value(dst_op) && g_reg_table.cur_regs[RAX]->has_value)
			{
				// rax instead of operands[0] is the destination
				insn->annotate = 1;
				val = g_reg_table.cur_regs[RAX]->value * get_op_value(dst_op, op_size);
				val &= mask;
				set_reg_value_at_pc(RAX, val, insn->pc);
			}
			else
			{
				if (insn->num_operand == 1)
					set_reg_unknown_at_pc(RAX, insn->pc);
				else
					set_op_unknown(dst_op, insn->pc);
			}
		}
	}
	else if (strncmp(insn->opcode_name, "idiv", 4) == 0)
	{
		process_binary_op_insn(insn, dst_op, src_op, DIVIDE);
	}
	else if (strncmp(insn->opcode_name, "inc", 3) == 0)
	{
		process_unary_op_insn(insn, dst_op, INCREMENT);
	}
	else if (strncmp(insn->opcode_name, "dec", 3) == 0)
	{
		process_unary_op_insn(insn, dst_op, DECREMENT);
	}
	else if (strncmp(insn->opcode_name, "and", 3) == 0)
	{
		process_binary_op_insn(insn, dst_op, src_op, BITWISE_AND);
	}
	else if (strncmp(insn->opcode_name, "or", 2) == 0)
	{
		process_binary_op_insn(insn, dst_op, src_op, BITWISE_OR);
	}
	else if (strncmp(insn->opcode_name, "not", 3) == 0)
	{
		process_unary_op_insn(insn, dst_op, BITWISE_NOT);
	}
	else if (strncmp(insn->opcode_name, "xor", 3) == 0)
	{
		if (insn->operands[0].type == CA_OP_REGISTER && insn->operands[1].type == CA_OP_REGISTER
			&& insn->operands[0].reg.index == insn->operands[1].reg.index)
		{
			insn->annotate = 1;
			val = 0;
			set_op_value(dst_op, 0, insn->pc);
		}
		else
			process_binary_op_insn(insn, dst_op, src_op, BITWISE_XOR);
	}
	else if (strncmp(insn->opcode_name, "shr", 3) == 0
			|| strncmp(insn->opcode_name, "sar", 3) == 0)
	{
		// shift right
		process_binary_op_insn(insn, dst_op, src_op, BITWISE_SHIFT_RIGHT);
	}
	else if (strncmp(insn->opcode_name, "shl", 3) == 0
			|| strncmp(insn->opcode_name, "sal", 3) == 0)
	{
		// shift left
		process_binary_op_insn(insn, dst_op, src_op, BITWISE_SHIFT_LEFT);
	}
	else if (strncmp(insn->opcode_name, "rol", 3) == 0)
	{
		// rotate left
		process_binary_op_insn(insn, dst_op, src_op, ROTATE_LEFT);
	}
	else if (strncmp(insn->opcode_name, "ror", 3) == 0)
	{
		// rotate right
		process_binary_op_insn(insn, dst_op, src_op, ROTATE_RIGHT);
	}
	else if (strncmp(insn->opcode_name, "rcl", 3) == 0
			|| strncmp(insn->opcode_name, "rcr", 3) == 0)
	{
		// rotate through carry left/right
		set_op_unknown(dst_op, insn->pc);
	}
	else if (strncmp(insn->opcode_name, "set", 3) == 0)
	{
		// conditional set instruction
		if (insn->operands[0].type == CA_OP_MEMORY && known_op_value(dst_op))
		{
			insn->annotate = 1;
		}
		set_op_unknown(dst_op, insn->pc);
	}
	else if (strncmp(insn->opcode_name, "ret", 3) == 0)
	{
		// If we are here, this "ret" can't be the last instruction of the function
		// i.e. there are multiple exits, we need to find out how we are branched here
		adjust_table_after_absolute_branch(insn->pc);
	}
	else if (strncmp(insn->opcode_name, "enter", 5) == 0)
	{
		// it is equivelent to three instructions
		//     push rbp
		//     mov rbp, rsp
		//     sub nbytes, rsp
		if (insn->operands[0].type == CA_OP_IMMEDIATE)
		{
			size_t rsp = g_reg_table.cur_regs[RSP]->value;
			val = get_op_value(&insn->operands[0], op_size);
			set_reg_value_at_pc(RSP, rsp - val, insn->pc);
		}
		//else
		//	(*info->fprintf_func)(info->stream, "internal error: unexpected operand");
	}
	// nop is alias to "xchg eax,eax"
	/*else if (strncmp(insn->opcode_name, "xchg", 4) == 0
		&& (insn->num_operand == 0
			|| (insn->num_operand == 2 && insn->operands[0].type == CA_OP_REGISTER && insn->operands[1].type == CA_OP_REGISTER && insn->operands[0].reg.index == RAX && insn->operands[1].reg.index == RAX) ) )
	{
	}*/
}

/*
 * Callback functions for disassembler
 */
static int ATTRIBUTE_PRINTF (2, 3)
fprintf_disasm (void *stream, const char *format, ...)
{
	va_list args;

	va_start (args, format);
	vfprintf_filtered (stream, format, args);
	va_end (args);
	/* Something non -ve.  */
	return 0;
}

static void
dis_asm_memory_error (int status, bfd_vma memaddr,
		      struct disassemble_info *info)
{
	memory_error (status, memaddr);
}

static void
dis_asm_print_address (bfd_vma addr, struct disassemble_info *info)
{
	print_address (addr, info->stream);
}

static int
dis_asm_read_memory (bfd_vma memaddr, gdb_byte *myaddr, unsigned int len,
		     struct disassemble_info *info)
{
	return target_read_memory (memaddr, myaddr, len);
}

static void
mem_ui_file_put (void *object, const char *buffer, long length)
{
	char** strp = (char**) object;
	char* dupstr = (char*) malloc(length + 1);
	strncpy(dupstr, buffer, length);
	dupstr[length] = '\0';
	*strp = dupstr;
}

/*
 * 	Return number of instructions disassembled
 */
static int dump_insns(struct decode_control_block* decode_cb)
{
	struct gdbarch *gdbarch = decode_cb->gdbarch;
	CORE_ADDR low = decode_cb->func_start;
	CORE_ADDR high = decode_cb->func_end;

	int num_insns = 0;
	CORE_ADDR pc;

	struct disassemble_info di;
	struct ui_file *mem_file = mem_fileopen();

	init_disassemble_info (&di, mem_file, fprintf_disasm);
	di.flavour = bfd_target_unknown_flavour;
	di.memory_error_func = dis_asm_memory_error;
	di.print_address_func = dis_asm_print_address;
	di.read_memory_func = dis_asm_read_memory;
	di.arch = gdbarch_bfd_arch_info (gdbarch)->arch;
	di.mach = gdbarch_bfd_arch_info (gdbarch)->mach;
	di.endian = gdbarch_byte_order (gdbarch);
	di.application_data = gdbarch;
	di.disassembler_options = "att"; //att_flavor;
	disassemble_init_for_target (&di);
	decode_cb->di = &di;

	// Set to initial state
	init_dis_insn_buffer();

	for (pc = low; pc < high;)
	{
		struct ca_dis_insn* insn;

		// bail out if user breaks
		if (user_request_break())
			break;

		insn = get_new_dis_insn();
		memset(insn, 0, sizeof(struct ca_dis_insn));
		decode_cb->insn = insn;
		insn->pc = pc;
		// disassemble one instruction
		pc += ca_print_insn_i386 (pc, decode_cb);
		// record the result
		ui_file_put (mem_file, mem_ui_file_put, &insn->dis_string);
		ui_file_rewind(mem_file);
		num_insns++;
	}

	// clean up
	ui_file_delete(mem_file);

	return num_insns;
}

/*
 * Stack values are spots on thread stack memory,
 *   where local variables, temporaries are places
 */
static void init_stack_vars(void)
{
	g_num_stack_vars = 0;
}

static void reset_stack_vars(void)
{
	unsigned int i;
	for (i = 0; i < g_num_stack_vars; i++)
	{
		struct ca_stack_var* sval = &g_stack_vars[i];
		if (sval->sym_name)
			free(sval->sym_name);
	}
	if (g_num_stack_vars > 0)
		memset(g_stack_vars, 0, g_num_stack_vars * sizeof(struct ca_stack_var));
	g_num_stack_vars = 0;
}

static struct ca_stack_var* get_stack_var(address_t saddr)
{
	unsigned int i;
	for (i = 0; i < g_num_stack_vars; i++)
	{
		struct ca_stack_var* sval = &g_stack_vars[i];
		if (sval->stack_addr == saddr)
			return sval;
	}
	return NULL;
}

static struct ca_stack_var* get_new_stack_var(address_t saddr)
{
	struct ca_stack_var* sval = get_stack_var(saddr);
	if (sval)
		return sval;

	// the address is first seen
	if (g_num_stack_vars >= g_stack_vars_capacity)
	{
		if (g_stack_vars_capacity == 0)
			g_stack_vars_capacity = STACK_ARRAY_INIT_CAP;
		else
			g_stack_vars_capacity *= 2;
		g_stack_vars = realloc(g_stack_vars, g_stack_vars_capacity * sizeof(struct ca_stack_var));
		memset(g_stack_vars + g_num_stack_vars, 0, (g_stack_vars_capacity - g_num_stack_vars) * sizeof(struct ca_stack_var));
	}
	return &g_stack_vars[g_num_stack_vars++];
}

static void set_stack_sym_type(char* sym_name, struct type* type, address_t saddr)
{
	if (sym_name || type)
	{
		// get_new_stack_var may return an existing one
		struct ca_stack_var* sval = get_new_stack_var(saddr);
		sval->stack_addr = saddr;
		// Assume one stack address is for one local variable only
		// we don't change its sym/type once it is set
		// Note: this is a simplistic approach for now
		if (sym_name && !sval->sym_name)
			sval->sym_name = strdup(sym_name);
		if (type && !sval->type)
			sval->type = type;
	}
}

/*
 * Initialize register table before analyzing instructions
 * set all registers to input values
 */
static void init_reg_table(struct ca_reg_value* regs)
{
	unsigned int i;
	for (i = 0; i < TOTAL_REGS; i++)
	{
		struct ca_reg_value* reg = get_new_reg(i);
		memcpy(reg, &regs[i], sizeof(struct ca_reg_value));
		reg->pc = 0;
	}
	// ground source references
	memset(regs, 0, REG_SET_SZ);
}

/*
 * Reset a register table
 */
static void reset_reg_table(void)
{
	struct ca_reg_table* table = &g_reg_table;
	unsigned int i;
	for (i = 0; i < TOTAL_REGS; i++)
	{
		struct ca_reg_vector* vec = &table->vecs[i];
		if (vec->finish > vec->start)
		{
			struct ca_reg_value* cursor;
			for (cursor = vec->start; cursor < vec->finish; cursor++)
			{
				if (cursor->sym_name)
					free(cursor->sym_name);
			}
			// clean the memory and reset finish pointer
			memset(vec->start, 0, (char*)vec->end_of_storage - (char*)vec->start);
			vec->finish = vec->start;
		}
	}
}

/*
 * Check invariants of the register table
 */
static void validate_reg_table(void)
{
	struct ca_reg_table* table = &g_reg_table;
	unsigned int i;
	for (i = 0; i < TOTAL_REGS; i++)
	{
		struct ca_reg_vector* vec = &table->vecs[i];
		if (vec->finish > vec->start)
		{
			struct ca_reg_value* cursor;
			for (cursor = vec->start + 1; cursor < vec->finish; cursor++)
			{
				if (cursor->pc <= (cursor - 1)->pc)
				{
					CA_PRINT("Internal error: register table is inconsistent\n");
					CA_PRINT("\tregister(%d) pc="PRINT_FORMAT_POINTER"\n", i, cursor->pc);
					break;
				}
			}
		}
	}
}

/*
 * Add a new value
 */
static void set_reg_value_at_pc(unsigned int reg_idx, size_t val, CORE_ADDR pc)
{
	struct ca_reg_value* cur = get_new_reg(reg_idx);
	cur->pc = pc;
	cur->has_value = 1;
	cur->value = val;
}

static void set_cur_reg_value(unsigned int reg_idx, size_t val)
{
	struct ca_reg_value* reg = g_reg_table.cur_regs[reg_idx];
	if (!reg->has_value)
	{
		reg->has_value = 1;
		reg->value = val;
	}
}

/*
 * Register is unknown at pc
 */
void set_reg_unknown_at_pc(unsigned int reg_idx, CORE_ADDR pc)
{
	struct ca_reg_value* cur = g_reg_table.cur_regs[reg_idx];
	// if current value is known already, skip it.
	if (!REG_KNOWN(cur))
		return;
	// A new register value is unknown at born
	cur = get_new_reg(reg_idx);
	cur->pc = pc;
}

/*
 * Return a register's value structure at given instruction address "pc"
 */
static struct ca_reg_value* get_reg_at_pc(unsigned int reg_idx, CORE_ADDR pc)
{
	struct ca_reg_vector* vec = &g_reg_table.vecs[reg_idx];
	struct ca_reg_value* cursor;
	for (cursor = vec->start; cursor < vec->finish; cursor++)
	{
		// exact match of address
		if (cursor->pc == pc)
			return cursor;
		// we have passed the address
		else if (cursor->pc > pc)
			break;
	}
	return NULL;
}

/*
 * Create a new value at the end of given reigister's vector in table
 * 	handle buffer expansion; update current register pointer as well
 */
static struct ca_reg_value* get_new_reg(unsigned int reg_idx)
{
	struct ca_reg_value* reg;
	struct ca_reg_vector* vec = &g_reg_table.vecs[reg_idx];
	if (vec->finish == vec->end_of_storage)
	{
		size_t capacity;
		size_t old_size;
		if (vec->start)
		{
			old_size = vec->finish - vec->start;
			capacity = old_size * 2;
		}
		else
		{
			old_size = 0;
			capacity = INIT_REG_ARRAY_SZ;
		}
		vec->start = (struct ca_reg_value*) realloc(vec->start, capacity * sizeof(struct ca_reg_value));
		vec->finish = vec->start + old_size;
		// zero new memory
		memset(vec->finish, 0, (capacity - old_size) * sizeof(struct ca_reg_value));
		vec->end_of_storage = vec->start + capacity;
	}
	reg = vec->finish++;
	g_reg_table.cur_regs[reg_idx] = reg;
	return reg;
}

/*
 * We just see an absolute branch instruction, e.g. "jmp", "ret", etc.
 *  therefore, function execution is NOT contiguous at this spot
 * 	find the instruction that branches to here and set the register context
 */
static void adjust_table_after_absolute_branch(CORE_ADDR pc)
{
	unsigned int insn_index, reg_index;
	CORE_ADDR offset = 0;
	struct ca_dis_insn* branch_insn = NULL;

	// find a branch instruction that branches to an address after "pc"
	for (insn_index = 0; insn_index < g_num_insns; insn_index++)
	{
		struct ca_dis_insn* insn = &g_insns_buffer[insn_index];
		if (insn->pc >= pc)
			break;
		if (insn->jmp && insn->branch_pc == pc)
		{
			branch_insn = insn;
			break;
		}
		else if (insn->branch && insn->branch_pc >= pc)
		{
			if (!branch_insn || offset > insn->branch_pc - pc)
			{
				branch_insn = insn;
				if (insn->branch_pc == pc)
					break;
				offset = insn->branch_pc - pc;
			}
		}
	}
	if (!branch_insn)
		return;

	// position current pointers to branch spot
	set_current_reg_pointers(branch_insn);

	// revert values in register table to those that before branch spot
	for (reg_index = 0; reg_index < TOTAL_REGS; reg_index++)
	{
		struct ca_reg_vector* vec = &g_reg_table.vecs[reg_index];
		struct ca_reg_value* reg = g_reg_table.cur_regs[reg_index];
		struct ca_reg_value* latest = vec->finish - 1;
		// adjust only the old value is different from current one
		if (reg_index != RIP && reg != latest &&
			(reg->type != latest->type || !is_same_string(reg->sym_name, latest->sym_name)))
		{
			// Register value has changed since branch spot, revert it
			struct ca_reg_value* new_reg = get_new_reg(reg_index);
			memcpy(new_reg, reg, sizeof(struct ca_reg_value));
			new_reg->pc = pc - 1;	// fake an address slightly before "pc"
			if (new_reg->sym_name)
				new_reg->sym_name = strdup(new_reg->sym_name);
		}
	}
}

/*
 * Set all current pointers in table point to values right before "pc"
 * 		beware: value at "pc" is the result of instruction
 */
static void set_current_reg_pointers(struct ca_dis_insn* insn)
{
	struct ca_reg_table* table = &g_reg_table;
	unsigned int i;
	for (i = 0; i < TOTAL_REGS; i++)
	{
		struct ca_reg_vector* vec = &table->vecs[i];
		struct ca_reg_value* reg = table->cur_regs[i];
		if (reg->pc >= insn->pc)
			reg = vec->start + 1;
		while (reg < vec->finish)
		{
			if (reg->pc >= insn->pc)
			{
				if (!insn->push)	// push instruction is an exception
					reg--;
				break;
			}
			reg++;
		}
		if (reg >= vec->finish)
			reg = vec->finish - 1;
		table->cur_regs[i] = reg;
	}
}

static void set_reg_table_at_pc(struct ca_reg_value* regs, CORE_ADDR pc)
{
	unsigned int i;
	for (i = 0; i < TOTAL_REGS; i++)
	{
		struct ca_reg_value* reg = &regs[i];
		if (REG_KNOWN(reg))
		{
			struct ca_reg_value* cur_reg = g_reg_table.cur_regs[i];
			struct ca_reg_value* dst;
			if (cur_reg->pc == pc)
			{
				dst = cur_reg;
				if (dst->sym_name)
					free(dst->sym_name);
			}
			else
				dst = get_new_reg(i);
			// shallow copy, ownership is transfered
			memcpy(dst, reg, sizeof(struct ca_reg_value));
			dst->pc = pc;
		}
	}
	// ground source references
	memset(regs, 0, REG_SET_SZ);
}

/*
 * Instruction buffer
 */
static struct ca_dis_insn* get_new_dis_insn(void)
{
	struct ca_dis_insn* insn;
	// prepare buffer
	if (g_num_insns >= g_insns_buffer_capacity)
	{
		if (g_insns_buffer_capacity == 0)
			g_insns_buffer_capacity = INSN_BUFFER_INIT_CAP;
		else
			g_insns_buffer_capacity *= 2;
		g_insns_buffer = realloc(g_insns_buffer, g_insns_buffer_capacity * sizeof(struct ca_dis_insn));
	}
	if (!g_insns_buffer)
	{
		CA_PRINT("Fatal: Out-of_memory\n");
		return NULL;
	}

	insn = &g_insns_buffer[g_num_insns];
	g_num_insns++;
	return insn;
}

static void init_dis_insn_buffer(void)
{
	unsigned int i;
	for (i = 0; i < g_num_insns; i++)
	{
		struct ca_dis_insn* insn = &g_insns_buffer[i];
		if (insn->dis_string)
		{
			free(insn->dis_string);
			insn->dis_string = NULL;
		}
	}
	g_num_insns = 0;
}

/*
 * Instruction operands
 */

// return the virtual address of memory operand,
//        0 if it has unknown base or index register value
static bfd_vma get_address(struct ca_operand* op)
{
	if (op->type == CA_OP_MEMORY)
	{
		bfd_vma base, index, mem_addr;
		if (op->mem.base_reg.name)
		{
			struct ca_reg_value* base_reg = g_reg_table.cur_regs[op->mem.base_reg.index];
			if (base_reg->has_value)
				base = base_reg->value;
			else
				return 0;
		}
		else
			base = 0;
		if (op->mem.index_reg.name)
		{
			struct ca_reg_value* index_reg = g_reg_table.cur_regs[op->mem.index_reg.index];
			if (index_reg->has_value)
				index = index_reg->value;
			else
				return 0;
		}
		else
			index = 0;
		mem_addr = base + index * (1 << op->mem.scale) + op->mem.disp.immediate;
		return mem_addr;
	}
	return 0;
}

// return the operand in the form of [base_reg + offset]
/*static void get_location(struct ca_operand* op, address_t* location, int* offset)
{
	if (op->type == CA_OP_MEMORY)
	{
		if (op->mem.base_reg.name && !op->mem.index_reg.name)
		{
			struct ca_reg_value* base_reg = g_reg_table.cur_regs[op->mem.base_reg.index];
			if (base_reg->has_value)
			{
				*location = base_reg->value;
				*offset = op->mem.disp.immediate;
			}
		}
	}
}*/

// return true if the operand's value is known
static int known_op_value(struct ca_operand* op)
{
	int rc = 0;

	if (op->type == CA_OP_REGISTER)
		rc = g_reg_table.cur_regs[op->reg.index]->has_value;
	else if (op->type == CA_OP_IMMEDIATE)
		rc = 1;
	else if (op->type == CA_OP_MEMORY)
	{
		bfd_vma mem_addr = get_address(op);
		if (mem_addr)
		{
			char val;
			if (target_read_memory(mem_addr, (bfd_byte*)&val, sizeof(val)) == 0)
				rc = 1;
		}
	}
	return rc;
}

// return true if the operand's value is on stack and known
static int is_stack_address(struct ca_operand* op)
{
	bfd_vma mem_addr = get_address(op);
	if (mem_addr >= g_debug_context.sp
		&& mem_addr < g_debug_context.segment->m_vaddr + g_debug_context.segment->m_vsize)
	{
		return 1;
	}
	return 0;
}

// Return symbol/type of the operand if known
static void
get_op_symbol_type(struct ca_operand* op, int lea,
				char** psymname, struct type** ptype, int* pvptr)
{
	if (op->type == CA_OP_REGISTER)
	{
		struct ca_reg_value* reg = g_reg_table.cur_regs[op->reg.index];
		if (reg->sym_name && psymname)
			*psymname = strdup(reg->sym_name);
		*ptype = reg->type;
	}
	else if (op->type == CA_OP_MEMORY)
	{
		struct ca_stack_var* sval;
		address_t addr = get_address(op);
		// if the destination is a known local variable, print it out
		if (is_stack_address(op) && (sval = get_stack_var(addr)) )
		{
			if (sval->sym_name)
				*psymname = strdup(sval->sym_name);
			*ptype = sval->type;
		}
		// The source is in the form of [base+offset]
		else if (op->mem.base_reg.name && !op->mem.index_reg.name)
		{
			struct ca_reg_value* base_reg = g_reg_table.cur_regs[op->mem.base_reg.index];
			struct type* type = base_reg->type;
			// operand should be a pointer type
			if (type
				&& (TYPE_CODE(type) == TYPE_CODE_PTR || TYPE_CODE(type) == TYPE_CODE_REF))
			{
				int is_vptr = 0;
				char namebuf[NAME_BUF_SZ];
				struct type* field_type = get_struct_field_type_and_name(TYPE_TARGET_TYPE(type), op->mem.disp.immediate, lea, namebuf, NAME_BUF_SZ, &is_vptr);
				if (field_type)
				{
					if (pvptr)
						*pvptr = is_vptr;
					// type
					if (lea)
						field_type = lookup_pointer_type(field_type);
					*ptype = field_type;
					// symbol name
					if (psymname && base_reg->sym_name)
					{
						// new symbol is '&' + base_name + "->" + field_name + '\0'
						size_t baselen = strlen(base_reg->sym_name);
						size_t namelen = (lea ? 1 : 0) + baselen + 2 + strlen(namebuf) + 1;
						char* cursor = malloc(namelen);
						*psymname = cursor;
						if (lea)
							*cursor++ = '&';
						strncpy(cursor, base_reg->sym_name, baselen);
						cursor += baselen;
						if (TYPE_CODE(base_reg->type) == TYPE_CODE_PTR)
						{
							*cursor++ = '-';
							*cursor++ = '>';
						}
						else
							*cursor++ = '.';
						strcpy(cursor, namebuf);
					}
				}
			}
		}
	}
}

// return the operand's value, assuming it is known or can be computed
static size_t get_op_value(struct ca_operand* op, size_t op_size)
{
	size_t rs = 0;
	unsigned int sz = sizeof(rs);

	if (op_size > 0)
		sz = op_size;

	if (op->type == CA_OP_REGISTER)
	{
		size_t mask = (size_t)(-1);
		mask = mask >> ((sz - 8) * 8);
		rs = g_reg_table.cur_regs[op->reg.index]->value & mask;
	}
	else if (op->type == CA_OP_IMMEDIATE)
		rs = (size_t) op->immed.immediate;
	else if (op->type == CA_OP_MEMORY)
	{
		bfd_vma mem_addr = get_address(op);
		if (g_ptr_bit == 32)
			sz = 4;
		target_read_memory(mem_addr, (bfd_byte*)&rs, sz);
	}
	return rs;
}

static void set_op_value(struct ca_operand* op, size_t val, CORE_ADDR pc)
{
	if (op->type == CA_OP_REGISTER)
	{
		set_reg_value_at_pc(op->reg.index, val, pc);
	}
	/*else if (op->type == CA_OP_MEMORY)
	{
		// remember values of local (stack) variables ?
	}*/
}

// mark the operand is unknown from now on
static void set_op_unknown(struct ca_operand* op, CORE_ADDR pc)
{
	if (op->type == CA_OP_REGISTER)
	{
		set_reg_unknown_at_pc(op->reg.index, pc);
	}
	/*else if (op->type == CA_OP_MEMORY)*/
}

/*
 * The most common instruction of all is the "mov" family
 * This function handles the propagation of value/symbol/type for src to dst
 */
static void
process_mov_insn(struct ca_dis_insn* insn,
				struct ca_operand* dst_op,
				struct ca_operand* src_op)
{
	size_t val = 0;
	size_t op_size = insn->op_size;
	int has_value = 0;
	int is_stack = 0;

	if (dst_op->type == CA_OP_MEMORY && is_stack_address(dst_op))
		is_stack = 1;

	// Value propagation rules
	if (insn->lea)
	{
		val = get_address(src_op);
		if (val)
			has_value = 1;
	}
	else if (src_op->type == CA_OP_IMMEDIATE
		|| (src_op->type == CA_OP_MEMORY && known_op_value(src_op)))
	{
		// source is an immediate or readable memory
		val = get_op_value(src_op, op_size);
		has_value = 1;
	}
	else if (is_stack)
	{
		// destination is readable stack memory
		val = get_op_value(dst_op, op_size);
		has_value = 1;
		// source operand deduced from destination
		// this should be true for x86 arch since dst is memory type
		if (src_op->type == CA_OP_REGISTER)
			set_cur_reg_value(src_op->reg.index, val);
	}
	else if (known_op_value(src_op))
	{
		// source is known register
		val = get_op_value(src_op, op_size);
		has_value = 1;
	}
	else if (dst_op->type == CA_OP_MEMORY && known_op_value(dst_op))
	{
		// destination is readable non-stack memory
		val = get_op_value(dst_op, op_size);
		has_value = 1;
		// this should be true for x86 arch since dst is memory type
		if (src_op->type == CA_OP_REGISTER)
			set_cur_reg_value(src_op->reg.index, val);
	}

	set_op_value_symbol_type(insn, src_op, dst_op, has_value, val);
}

static void
set_op_value_symbol_type(struct ca_dis_insn* insn,
		struct ca_operand* sym_op,
		struct ca_operand* dst_op,
		int has_value,
		size_t val)
{
	char* sym_name = NULL;
	struct type* type = NULL;
	int is_vptr = 0;

	// source symbol/type
	get_op_symbol_type(sym_op, insn->lea, &sym_name, &type, &is_vptr);
	// Record the information transfered from source to destination
	set_dst_op(insn, dst_op, has_value, val, sym_name, type, is_vptr);

	// free symbol string if any
	if (sym_name)
		free (sym_name);
}

static void process_unary_op_insn(struct ca_dis_insn* insn,
		struct ca_operand* dst_op, enum CA_OPERATOR op)
{
	size_t val = 0;
	int op_size = insn->op_size;
	size_t mask = (size_t)(-1);
	int has_value = 0;

	if (op_size > 0)
		mask = mask >> ((8 - op_size) * 8);

	if (known_op_value(dst_op))
	{
		insn->annotate = 1;
		switch (op)
		{
		case INCREMENT:
			val = get_op_value(dst_op, op_size) + 1;
			break;
		case DECREMENT:
			val = get_op_value(dst_op, op_size) - 1;
			break;
		case BITWISE_NOT:
			val = ~get_op_value(dst_op, op_size);
			break;
		default:
			break;
		}
		val &= mask;
		has_value = 1;
	}

	set_op_value_symbol_type(insn, dst_op, dst_op, has_value, val);
}

/*
 * Common binary operation are: "+,-,*,/", i.e. "dst op src => dst"
 */
static void
process_binary_op_insn(struct ca_dis_insn* insn,
						struct ca_operand* dst_op,
						struct ca_operand* src_op,
						enum CA_OPERATOR op)
{
	size_t val = 0;
	int op_size = insn->op_size;
	size_t mask = (size_t)(-1);
	int has_value = 0;
	struct ca_reg_value* dst_reg = NULL;
	char* sym_name = NULL;
	struct type* type = NULL;
	int is_vptr = 0;

	if (dst_op->type == CA_OP_REGISTER)
		dst_reg = g_reg_table.cur_regs[dst_op->reg.index];

	if (op_size > 0)
		mask = mask >> ((8 - op_size) * 8);

	// value can be computed only both operands are known
	if (known_op_value(src_op) && known_op_value(dst_op))
	{
		size_t dst_val = get_op_value(dst_op, op_size) & mask;
		size_t src_val = get_op_value(src_op, op_size) & mask;
		has_value = 1;
		switch(op)
		{
		case ADD:
			val = dst_val + src_val;
			break;
		case SUBTRACT:
			val = dst_val - src_val;
			break;
		case MULTIPLY:
			val = dst_val * src_val;
			break;
		case DIVIDE:
			val = dst_val / src_val;
			break;
		case BITWISE_AND:
			val = dst_val & src_val;
			break;
		case BITWISE_OR:
			val = dst_val | src_val;
			break;
		case BITWISE_XOR:
			val = dst_val ^ src_val;
			break;
		case BITWISE_SHIFT_RIGHT:
			val = dst_val >> src_val;
			break;
		case BITWISE_SHIFT_LEFT:
			val = dst_val << src_val;
			break;
		case ROTATE_LEFT:
		case ROTATE_RIGHT:
			val = bit_rotate (dst_val, src_val, op, op_size);
			break;
		default:	// we shouldn't be here
			break;
		}
		val &= mask;
	}

	// Special cases
	if (dst_reg && dst_reg->type)	// dst is a register with known type
	{
		if (op == ADD && src_op->type == CA_OP_IMMEDIATE)
		{
			// A pointer to an object is added with a fixed offset, e.g. "add 0x20, %rdi"
			// this is equivalent to "lea 0x20(%rdi), %rdi"
			struct ca_operand my_src;
			my_src.type = CA_OP_MEMORY;
			my_src.mem.base_reg.index = dst_op->reg.index;
			my_src.mem.base_reg.name  = dst_op->reg.name;
			my_src.mem.base_reg.size  = dst_op->reg.size;
			my_src.mem.disp.immediate = src_op->immed.immediate;
			my_src.mem.index_reg.name = NULL;
			my_src.mem.scale = 0;
			get_op_symbol_type(&my_src, 1, &sym_name, &type, NULL);
		}
		else
			type = dst_reg->type;
	}

	// Set value/symbol/type
	set_dst_op(insn, dst_op, has_value, val, sym_name, type, is_vptr);

	// free symbol string if any
	if (sym_name)
		free (sym_name);
}

static void set_dst_op(struct ca_dis_insn* insn, struct ca_operand* dst_op,
		int has_value, size_t val, char* symname, struct type* type, int is_vptr)
{
	if (has_value || symname || type)
	{
		insn->annotate = 1;
		if (dst_op->type == CA_OP_REGISTER)
		{
			struct ca_reg_value* dst_reg = get_new_reg(dst_op->reg.index);
			dst_reg->has_value = has_value;
			dst_reg->pc = insn->pc;
			if (symname)
				dst_reg->sym_name = strdup(symname);
			dst_reg->type = type;
			dst_reg->value = val;
			dst_reg->vptr = is_vptr;
		}
		if (dst_op->type == CA_OP_MEMORY && is_stack_address(dst_op))
		{
			address_t saddr = get_address(dst_op);
			set_stack_sym_type(symname, type, saddr);
		}
	}
	else
		set_op_unknown(dst_op, insn->pc);
}

/* Put DISP in BUF as signed hex number.  */
static void print_displacement(char *buf, bfd_vma disp)
{
	bfd_signed_vma val = disp;
	char tmp[30];
	int i, j = 0;

	if (val < 0)
	{
		buf[j++] = '-';
		val = -disp;
	}

	buf[j++] = '0';
	buf[j++] = 'x';

	sprintf_vma(tmp, (bfd_vma) val);
	for (i = 0; tmp[i] == '0'; i++)
		continue;
	if (tmp[i] == '\0')
		i--;
	strcpy(buf + j, tmp + i);
}

static void print_one_operand(struct ui_out* uiout, struct ca_operand* op, size_t op_size)
{
	char dispbuf[32];
	if (op->type == CA_OP_REGISTER)
	{
		ui_out_text(uiout, op->reg.name);
	}
	else if (op->type == CA_OP_IMMEDIATE)
	{
		print_displacement(dispbuf, op->immed.immediate);
		ui_out_text(uiout, dispbuf);
	}
	else if (op->type == CA_OP_MEMORY)
	{
		int need_addition_sign = 0;
		ui_out_text(uiout, "[");
		if (op->mem.base_reg.name)
		{
			ui_out_text(uiout,  op->mem.base_reg.name);
			need_addition_sign = 1;
		}
		if (op->mem.index_reg.name)
		{
			if (need_addition_sign)
				ui_out_text(uiout, "+");
			need_addition_sign = 1;
			ui_out_message(uiout, 0, "%s*%d", op->mem.index_reg.name, 1 << op->mem.scale);
		}
		if (op->mem.disp.immediate != 0)
		{
			print_displacement(dispbuf, op->mem.disp.immediate);
			if ((bfd_signed_vma)op->mem.disp.immediate > 0)
				ui_out_text(uiout, "+");
			ui_out_text(uiout, dispbuf);
		}
		ui_out_text(uiout, "]");
	}
}

static size_t bit_rotate(size_t val, size_t nbits, enum CA_OPERATOR dir, int size)
{
	int bits_travel = size * 8 - 1;
	for(; nbits > 0; nbits--)
	{
		size_t tmp;
		if (dir == ROTATE_RIGHT)
		{
			tmp = (val & 1) << bits_travel;
			val = val >> 1;
			val |= tmp;
		}
		else if (dir == ROTATE_LEFT)
		{
			tmp = (val & (1 << bits_travel)) >> bits_travel;
			val = val << 1;
			val |= tmp;
		}
	}
	return val;
}

// arguments may be NIL
static int is_same_string(const char* str1, const char* str2)
{
	int rc;

	if (!str1 && !str2)
		rc = 1;
	else if ( (str1 && !str2) || (!str1 && str2))
		rc = 0;
	else
	{
		if (strcmp(str1, str2) == 0)
			rc = 1;
		else
			rc = 0;
	}
	return rc;
}
