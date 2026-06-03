/*
 * x_dep.h
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */
#ifndef X_DEP_H_
#define X_DEP_H_


#include "x_common.h"

#define ITERATE_OVER_THREADS(cb) iterate_over_threads(cb, NULL)

#define THREAD_CB_RETURN_TYPE int
#define THREAD_CB_FUNC(info, data) thread_tcache(struct thread_info *info, void *data)
#define THREAD_CB_RETURN_CONT 0

#define CA_VALUE_TYPE(value) (value)->type()

#define CA_LOOKUP_SYMBOL(name) lookup_symbol(name, nullptr, SEARCH_VAR_DOMAIN, nullptr).symbol

#endif // X_DEP_H_
