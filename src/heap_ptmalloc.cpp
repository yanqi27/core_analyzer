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
	const size_t bufsz = 64;
	char buf[bufsz];
	memset(buf, 0, bufsz);
	if (!get_gv_value("__libc_version", buf, bufsz)) {
		CA_PRINT("Cannot get the \"__libc_version\" from the debugee, read it from the host machine. This might not be accurate.\n");
		version = gnu_get_libc_version();
	} else {
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
