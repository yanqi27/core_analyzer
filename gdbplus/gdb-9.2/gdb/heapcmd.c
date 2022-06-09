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

/***************************************************************************
* gdb commands
***************************************************************************/
static void
heap_command (const char *args, int from_tty)
{
	/* We depend on typed segments */
	if (!update_memory_segments_and_heaps())
		return;

	if (!args)
		args = "";
	gdb::unique_xmalloc_ptr<char> myargs(xstrdup(args));

	// remember to resume the current thread/frame
	scoped_restore_current_thread mythread;
	heap_command_impl(myargs.get());
}

static void
ref_command (const char *args, int from_tty)
{
	if (!args)
		error_no_arg (_("address"));

	/* We depend on typed segments */
	if (!update_memory_segments_and_heaps())
		return;

	gdb::unique_xmalloc_ptr<char> myargs(xstrdup(args));

	// remember to resume the current thread/frame
	scoped_restore_current_thread mythread;
	ref_command_impl(myargs.get());
}

static void
pattern_command (const char *args, int from_tty)
{
	if (!args)
		error_no_arg (_("address"));

	/* We depend on typed segments */
	if (!update_memory_segments_and_heaps())
		return;

	gdb::unique_xmalloc_ptr<char> myargs(xstrdup(args));

	// remember to resume the current thread/frame
	scoped_restore_current_thread mythread;
	pattern_command_impl(myargs.get());
}

static void
segment_command (const char *args, int from_tty)
{
	if (!update_memory_segments_and_heaps())
		return;

	if (!args)
		args = "";
	gdb::unique_xmalloc_ptr<char> myargs(xstrdup(args));

	segment_command_impl(myargs.get());
}

static void
include_free_command (const char *arg, int from_tty)
{
	g_skip_free = false;
	printf_filtered(_("Reference search will now include free heap memory blocks\n"));
}

static void
ignore_free_command (const char *arg, int from_tty)
{
	g_skip_free = true;
	printf_filtered(_("Reference search will now exclude free heap memory blocks (default)\n"));
}

static void
include_unknown_command (const char *arg, int from_tty)
{
	g_skip_unknown = false;
	printf_filtered(_("Reference search will now include all memory\n"));
}

static void
ignore_unknown_command (const char *arg, int from_tty)
{
	g_skip_unknown = true;
	printf_filtered(_("Reference search will now exclude memory with unknown storage type (default)\n"));
}

static void
assign_command (const char *args, int from_tty)
{
	// Parse user input options
	// argument is in the form of <start> <end>
	if (args)
	{
		address_t addr = 0, value = 0;
		char* options[MAX_NUM_OPTIONS];
		gdb::unique_xmalloc_ptr<char> myargs(xstrdup(args));
		int num_options = ca_parse_options(myargs.get(), options);

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
unassign_command (const char *args, int from_tty)
{
	if (!args)
		error_no_arg (_("address"));

	// Parse user input options
	// argument is a list of addresses
	// Parse user input options
	// argument is a list of addresses
	gdb::unique_xmalloc_ptr<char> myargs(xstrdup(args));
	char* options[MAX_NUM_OPTIONS];
	int num_options = ca_parse_options(myargs.get(), options);
	int i;
	for (i = 0; i < num_options; i++)
	{
		char* option = options[i];
		address_t addr = parse_and_eval_address (option);
		unset_value (addr);
	}
}

static void
info_local_command (const char *arg, int from_tty)
{
	print_func_locals ();
}

static void
buildid_command(const char *arg, int from_tty)
{
	print_build_ids ();
}

static void
dt_command (const char *args, int from_tty)
{
	if (!args)
		error_no_arg (_("type or variable name"));

	bool print_type = false;
	size_t min_sz = 0;
	size_t max_sz = 0;

	gdb::unique_xmalloc_ptr<char> myargs(xstrdup(args));
	char* options[MAX_NUM_OPTIONS];
	int num_options = ca_parse_options(myargs.get(), options);
	int i;
	for (i = 0; i < num_options; i++) {
		char* option = options[i];
		if (*option == '/') {
			if (strcmp(option, "/size") == 0 || strcmp(option, "/s") == 0) {
				if (i + 1 >= num_options) {
					CA_PRINT("size is expected\n");
					return;
				}
				min_sz = ca_eval_address(options[i + 1]);
				if (i + 2 < num_options) {
					max_sz = ca_eval_address(options[i + 2]);
				} else {
					max_sz = min_sz;
				}
				if (min_sz > max_sz) {
					CA_PRINT("Invalid size arguments\n");
					return;
				}
			} else {
				CA_PRINT("Invalid option: [%s]\n", option);
				return;
			}
		} else {
			print_type = true;
		}
		break;
	}
	if (print_type)
		print_type_layout (myargs.get());
	else
		search_types_by_size(min_sz, max_sz);
}

static void
obj_command (const char *args, int from_tty)
{
	if (!args)
		error_no_arg (_("type or variable name"));

	/* We depend on typed segments */
	if (!update_memory_segments_and_heaps())
		return;

	// remember to resume the current thread/frame
	scoped_restore_current_thread mythread;
	gdb::unique_xmalloc_ptr<char> myargs(xstrdup(args));
	char* options[MAX_NUM_OPTIONS];
	int num_options = ca_parse_options(myargs.get(), options);
	const char *expr = NULL;
	bool search_ref = false;
	bool obj_stats = false;
	for (int i = 0; i < num_options; i++) {
		char* option = options[i];
		if (strcmp(option, "/ref") == 0 || strcmp(option, "/r") == 0) {
			search_ref = true;
		} else if (strcmp(option, "/stats") == 0 || strcmp(option, "/s") == 0) {
			obj_stats = true;
		} else if (option[0] == '/') {
			CA_PRINT("invalid option\n");
			return;
		} else if (expr) {
			CA_PRINT("too many expressions\n");
			return;
		} else {
			expr = option;
		}
	}
	if (obj_stats) {
		display_object_stats();
	} else {
		search_cplusplus_objects_and_references(expr, search_ref, false);
	}
}

static void
shrobj_level_command (const char *arg, int from_tty)
{
	unsigned int level = 0;
	if (arg)
		level = parse_and_eval_address (arg);

	set_shared_objects_indirection_level(level);
}

static void
max_indirection_level_command (const char *arg, int from_tty)
{
	unsigned int level = 0;
	if (arg)
		level = parse_and_eval_address (arg);

	set_max_indirection_level(level);
}

#define IS_BLANK(c) ((c)==' ' || (c)=='\t')

static void
shrobj_command (const char *args, int from_tty)
{
	std::list<int> threads;

	/* We depend on typed segments */
	if (!update_memory_segments_and_heaps())
		return;

	if (args)
	{
		char* options[MAX_NUM_OPTIONS];
		gdb::unique_xmalloc_ptr<char> myargs(xstrdup(args));
		int num_options = ca_parse_options(myargs.get(), options);
		int i;
		for (i = 0; i < num_options; i++)
		{
			char* option = options[i];
			int tid = atoi(option);
			if (tid >= 0)
			{
				threads.push_front(tid);
			}
		}
	}

	// remember to resume the current thread/frame
	scoped_restore_current_thread mythread;

	find_shared_objects_by_threads(threads);
}

static void
decode_command (const char *args, int from_tty)
{
	/* We depend on typed segments */
	if (!update_memory_segments_and_heaps())
		return;

	if (!args)
		args = "";
	gdb::unique_xmalloc_ptr<char> myargs(xstrdup(args));

	// remember to resume the current thread/frame
	scoped_restore_current_thread mythread;

	decode_func(myargs.get());
}

static void
display_help_command (const char *arg, int from_tty)
{
    CA_PRINT("%s", ca_help_msg);
}

static void
switch_heap_command(const char *arg, int from_tty)
{
	if (!arg) {
		auto supported_heaps = get_supported_heaps();
		CA_PRINT("Please provide the heap manager name, currently supported heap managers: %s.\n", supported_heaps.c_str());
		return;
	}
	#ifdef WIN32
	if (1) {
		CA_PRINT("We dont support switch heap manager in Windows yet.\n");
		return;
	}
	#endif
	auto it = gCoreAnalyzerHeaps.find(arg);
	if (it != gCoreAnalyzerHeaps.end()) {
		CA_PRINT("switch to heap %s\n", arg);
		if (CA_HEAP != it->second) {
			CA_HEAP = it->second;
			CA_HEAP->init_heap();
		}
	} else {
		auto supported_heaps = get_supported_heaps();
		CA_PRINT("Please provide the heap manager name, currently supported heap managers: %s.\n", supported_heaps.c_str());	
	}
	return;
}
void
_initialize_heapcmd (void)
{
	add_cmd("ref", class_info, ref_command, _("Search for references to a given object.\n"
	    "ref <addr_exp>\n"
		"ref [/thread or /t] <addr_exp> <size> [level]"),
		&cmdlist);

	add_cmd("obj", class_info, obj_command, _("Search for objects that matches the type of the input expression; Stats of all objects\n"
	    "obj [/stats or /s]\n"
	    "obj [/ref or /r] <type|variable>"),
		&cmdlist);

	add_cmd("shrobj", class_info, shrobj_command, _("Find objects that currently referenced from multiple threads\n"
	    "shrobj [tid0] [tid1] [...]"),
		&cmdlist);

	add_cmd("heap", class_info, heap_command, _("Heap walk, query, memory usage statistics, leak check, etc.\n"
		"heap\n"
		"heap [/block or /b] <addr_exp>\n"
		"heap [/cluster or /c] <addr_exp>\n"
		"heap [/usage or /u] <var_exp>\n"
		"heap [/topblock or /tb] <num>\n"
		"heap [/topuser or /tu] <num>\n"
		"heap [/verbose or /v] [/leak or /l]\n"
		"heap [/m]"),
		&cmdlist);

	add_cmd("pattern", class_info, pattern_command, _("Reveal memory pattern\n"
	    "pattern <start> <end>"),
		&cmdlist);

	add_cmd("segment", class_info, segment_command, _("Display memory segment(s)\n"
	    "segment [address]"),
		&cmdlist);

	add_cmd("decode", class_info, decode_command, _("Disassemble current function with detail annotation of object context\n"
	    "decode %reg=<val> from=<addr> to=<addr>|end"),
		&cmdlist);

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
	add_cmd("switch_heap", class_info, switch_heap_command, _("switch another heap like pt, tc,"), &cmdlist);

	add_cmd("dt", class_info, dt_command, _("Display type (windbg style) that matches the input expression or size or size ragne\n"
	    "dt <type|variable>\n"
		"dt [/size or /s] <size> [<size-max>]"),
		&cmdlist);
	add_cmd("info_local", class_info, info_local_command, _("Display local variables"), &cmdlist);
	add_cmd("buildid", class_info, buildid_command, _("Display build-ids of target modules"), &cmdlist);
}
