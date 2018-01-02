/*
 * heapcmd.c
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */
#include "ref.h"
#include "heap.h"
#include "segment.h"
#include "search.h"
#include "decode.h"
#include "stl_container.h"

/***************************************************************************
* gdb commands
***************************************************************************/
static void
heap_command (char *args, int from_tty)
{
	struct cleanup *old_chain;

	/* We depend on typed segments */
	if (!update_memory_segments_and_heaps())
		return;
	old_chain = make_cleanup_restore_current_thread ();

	heap_command_impl(args);

	// remember to resume the current thread/frame
	do_cleanups (old_chain);
}

static void
ref_command (char *args, int from_tty)
{
	struct cleanup *old_chain;
	/* We depend on typed segments */
	if (!update_memory_segments_and_heaps())
		return;
	old_chain = make_cleanup_restore_current_thread ();

	ref_command_impl(args);

	// remember to resume the current thread/frame
	do_cleanups (old_chain);
}

static void
pattern_command (char *args, int from_tty)
{
	struct cleanup *old_chain;
	/* We depend on typed segments */
	if (!update_memory_segments_and_heaps())
		return;

	old_chain = make_cleanup_restore_current_thread ();

	pattern_command_impl(args);

	// remember to resume the current thread/frame
	do_cleanups (old_chain);
}

static void
segment_command (char *arg, int from_tty)
{
	if (!update_memory_segments_and_heaps())
		return;
	segment_command_impl(arg);
}

static void
include_free_command (char *arg, int from_tty)
{
	g_skip_free = false;
	printf_filtered(_("Reference search will now include free heap memory blocks\n"));
}

static void
ignore_free_command (char *arg, int from_tty)
{
	g_skip_free = true;
	printf_filtered(_("Reference search will now exclude free heap memory blocks (default)\n"));
}

static void
include_unknown_command (char *arg, int from_tty)
{
	g_skip_unknown = false;
	printf_filtered(_("Reference search will now include all memory\n"));
}

static void
ignore_unknown_command (char *arg, int from_tty)
{
	g_skip_unknown = true;
	printf_filtered(_("Reference search will now exclude memory with unknown storage type (default)\n"));
}

static void
assign_command (char *args, int from_tty)
{
	// Parse user input options
	// argument is in the form of <start> <end>
	if (args)
	{
		address_t addr = 0, value = 0;
		char* options[MAX_NUM_OPTIONS];
		int num_options = ca_parse_options(args, options);
		int i;
		if (num_options != 2)
		{
			CA_PRINT("Expect arguments: <address> <value>\n");
			return;
		}
		addr = parse_and_eval_address (options[0]);
		value = parse_and_eval_address (options[1]);
		set_value (addr, value);
	}
	else
		print_set_values ();
}

static void
unassign_command (char *args, int from_tty)
{
	// Parse user input options
	// argument is a list of addresses
	if (args)
	{
		char* options[MAX_NUM_OPTIONS];
		int num_options = ca_parse_options(args, options);
		int i;
		for (i = 0; i < num_options; i++)
		{
			char* option = options[i];
			address_t addr = parse_and_eval_address (option);
			unset_value (addr);
		}
	}
	else
		error_no_arg (_("address"));
}

static void
info_local_command (char *arg, int from_tty)
{
	print_func_locals ();
}

static void
dt_command (char *arg, int from_tty)
{
	char* type_or_expr;

	if (!arg)
		error_no_arg (_("type or variable name"));
	type_or_expr = strdup(arg);
	print_type_layout (type_or_expr);
	free (type_or_expr);
}

static void
obj_command (char *arg, int from_tty)
{
	struct cleanup *old_chain;

	if (!arg)
		error_no_arg (_("type or variable name"));

	/* We depend on typed segments */
	if (!update_memory_segments_and_heaps())
		return;

	old_chain = make_cleanup_restore_current_thread ();
	search_cplusplus_objects_and_references(arg, false);
	// remember to resume the current thread/frame
	do_cleanups (old_chain);
}

static void
shrobj_level_command (char *arg, int from_tty)
{
	unsigned int level = 0;
	if (arg)
		level = parse_and_eval_address (arg);

	set_shared_objects_indirection_level(level);
}

static void
max_indirection_level_command (char *arg, int from_tty)
{
	unsigned int level = 0;
	if (arg)
		level = parse_and_eval_address (arg);

	set_max_indirection_level(level);
}

#define IS_BLANK(c) ((c)==' ' || (c)=='\t')

static void
shrobj_command (char *args, int from_tty)
{
	struct CA_LIST* threads = NULL;
	struct cleanup *old_chain;

	/* We depend on typed segments */
	if (!update_memory_segments_and_heaps())
		return;

	threads = ca_list_new();
	if (args)
	{
		char* options[MAX_NUM_OPTIONS];
		int num_options = ca_parse_options(args, options);
		int i;
		for (i = 0; i < num_options; i++)
		{
			char* option = options[i];
			int tid = atoi(option);
			if (tid >= 0)
			{
				int* p = (int*) malloc(sizeof(int));
				*p = tid;
				ca_list_push_front(threads, p);
			}
		}
	}

	old_chain = make_cleanup_restore_current_thread ();
	find_shared_objects_by_threads(threads);
	// remember to resume the current thread/frame
	do_cleanups (old_chain);
	// cleanup thread list
	if (!ca_list_empty(threads))
	{
		int* p;
		ca_list_traverse_start(threads);
		while ( (p = (int*) ca_list_traverse_next(threads)))
			free (p);
	}
	ca_list_delete(threads);
}

static void
decode_command (char *arg, int from_tty)
{
	struct cleanup *old_chain;
	/* We depend on typed segments */
	if (!update_memory_segments_and_heaps())
		return;

	old_chain = make_cleanup_restore_current_thread ();

	decode_func(arg);

	// remember to resume the current thread/frame
	do_cleanups (old_chain);
}

static void
display_help_command (char *arg, int from_tty)
{
    CA_PRINT("%s", ca_help_msg);
}

void
_initialize_heapcmd (void)
{
	add_cmd("ref", class_info, ref_command, _("Search for references to a given object.\nref <addr_exp>\nref [/thread or /t] <addr_exp> <size> [level]"), &cmdlist);
	add_cmd("obj", class_info, obj_command, _("Search for object and reference to object of the same type as the input expression\nobj <type|variable>"), &cmdlist);
	add_cmd("shrobj", class_info, shrobj_command, _("Find objects that currently referenced from multiple threads\nshrobj [tid0] [tid1] [...]"), &cmdlist);

	add_cmd("heap", class_info, heap_command, _("Heap walk, heap data validation, memory usage statistics, etc.\n"
		"heap [/verbose or /v] [/leak or /l]\n"
		"heap [/block or /b] [/cluster or /c] <addr_exp>\n"
		"heap [/usage or /u] <var_exp>\n"
		"heap [/topblock or /tb] [/topuser or /tu] <num>\n"
		"heap [/m]\n"),
		&cmdlist);

	add_cmd("pattern", class_info, pattern_command, _("Reveal memory pattern\npattern <start> <end>"), &cmdlist);
	add_cmd("segment", class_info, segment_command, _("Display memory segments"), &cmdlist);
	add_cmd("decode", class_info, decode_command, _("Disassemble current function with detail annotation of object context\ndecode %reg=<val> from=<addr> to=<addr>|end"), &cmdlist);

	// Settings
	add_cmd("shrobj_level", class_info, shrobj_level_command, _("Set/Show the indirection level of shared-object search"), &cmdlist);
	add_cmd("max_indirection_level", class_info, max_indirection_level_command, _("Set/Show the maximum indirection level of reference search"), &cmdlist);
	add_cmd("assign", class_info, assign_command, _("Pretend the memory data is the given value\nassign [addr] [value]"), &cmdlist);
	add_cmd("unassign", class_info, unassign_command, _("Remove the fake value at the given address\nunassign <addr>"), &cmdlist);
	add_cmd("include_free", class_info, include_free_command, _("Reference search includes free heap memory blocks"), &cmdlist);
	add_cmd("ignore_free", class_info, ignore_free_command, _("Reference search excludes free heap memory blocks (default)"), &cmdlist);
	add_cmd("include_unknown", class_info, include_unknown_command, _("Reference search includes all memory"), &cmdlist);
	add_cmd("ignore_unknown", class_info, ignore_unknown_command, _("Reference search excludes memory with unknown storage type (default)"), &cmdlist);

	// Misc
	add_cmd("ca_help", class_info, display_help_command, _("Display core analyzer help"), &cmdlist);
	add_cmd("dt", class_info, dt_command, _("Display type (windbg style)\ndt <type|variable>"), &cmdlist);
	add_cmd("info_local", class_info, info_local_command, _("Display local variables"), &cmdlist);
}
