/*
* common functions for different pt malloc
* */

#include <gnu/libc-version.h>
#include <assert.h>

#include "segment.h"
#include "heap_ptmalloc.h"



namespace pt 
{


std::string read_libc_version()
{
	std::string version;
	struct symbol *sym = lookup_static_symbol("__libc_version", VAR_DOMAIN).symbol;
	if (sym == NULL) {
		CA_PRINT("Cannot get the \"__libc_version\" from the debugee, read it from the host machine. This might not be accurate.\n");
		version = gnu_get_libc_version();
	} else {
		struct value *val = value_of_variable(sym, 0);
		constexpr int bufsz = 64;
		char buf[bufsz];
		if (!read_memory_wrapper(NULL,  value_address(val), buf, TYPE_LENGTH(value_type(val)))) {
			CA_PRINT("Failed to read \"__libc_version\" from the debugee.\n");
			return version;
		}
		version = buf;
	}
	return version;
}

/*
 * Get the glibc version of the debugee
 */
bool
get_glibc_version(int *major, int *minor)
{
	std::string version = read_libc_version();
	if (version.empty())
		return false;
	auto dot_idx = version.find_first_of('.');
	*major = atoi(version.substr(0, dot_idx).c_str());
	*minor = atoi(version.substr(dot_idx+1).c_str());
	if (*major != 2)
	{
		CA_PRINT("This version of glibc %d.%d is not tested, please contact the owner\n",
				*major, *minor);
		return false;
	}

	return true;
}

}
