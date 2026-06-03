/*
 * x_dep.h
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */
#ifndef X_DEP_H_
#define X_DEP_H_

#include "x_common.h"
#include "gdbcmd.h"


#define CA_PRINT(format,args...) \
	printf_filtered(_(format), ##args)

#define ITERATE_OVER_THREADS() iterate_over_threads(thread_tcache, NULL)

#define THREAD_CB_RETURN_TYPE int
#define THREAD_CB_FUNC(info, data) thread_tcache(struct thread_info *info, void *data)
#define THREAD_CB_RETURN_CONT 0

#define CA_VALUE_TYPE(value) value_type(value)
#define CA_VALUE_ADDRESS(value) value_address(value)

#define CA_LOOKUP_SYMBOL(name) lookup_symbol(name, 0, VAR_DOMAIN, 0).symbol
#define CA_LOOKUP_SYMBOL_FUNC(name) lookup_symbol(name, 0, VAR_DOMAIN, 0).symbol
#define CA_LOOKUP_GLOBAL_SYMBOL(name) lookup_global_symbol(name, 0, VAR_DOMAIN).symbol

#endif // X_DEP_H_
