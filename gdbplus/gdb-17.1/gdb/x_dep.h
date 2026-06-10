/*
 * x_dep.h
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */
#ifndef X_DEP_H_
#define X_DEP_H_

#include "x_common.h"

#define ITERATE_OVER_THREADS() iterate_over_threads(thread_tcache)

#define THREAD_CB_RETURN_TYPE bool
#define THREAD_CB_FUNC(info, data) thread_tcache(struct thread_info *info)
#define THREAD_CB_RETURN_CONT false

#define CA_SYMBOL_TYPE(sym) (sym)->type()
#define CA_VALUE_TYPE(value) (value)->type()
#define CA_VALUE_ADDRESS(value) (value)->address()
#define CA_TYPE_LENGTH(type) (type)->length()
#define CA_TYPE_TARGET_TYPE(type) (type)->target_type()
#define CA_TYPE_CODE(type) (type)->code()

#define CA_LOOKUP_SYMBOL(name) lookup_symbol(name, nullptr, SEARCH_VAR_DOMAIN, nullptr).symbol
#define CA_LOOKUP_SYMBOL_FUNC(name) lookup_symbol(name, 0, SEARCH_FUNCTION_DOMAIN, 0).symbol
#define CA_LOOKUP_GLOBAL_SYMBOL(name) lookup_global_symbol(name, nullptr, SEARCH_VAR_DOMAIN).symbol

#define CA_TCMALLOC_PAGE_MAP2 "TCMalloc_PageMap2<35>::LEAF_BITS"
#define CA_TCMALLOC_PAGE_MAP3 "TCMalloc_PageMap3<35>::LEAF_BITS"

#define CA_VFPRINTF(stream, format, args) \
	gdb_vprintf ((ui_file *)stream, format, args)

#define CA_INIT_DISASSEMBLE_INFO(di, stream, fprintf_func, fprintf_styled_func) \
	init_disassemble_info(di, stream, fprintf_func, fprintf_styled_func)

#define CA_SPRINTF_VMA(bfd, buffer, val) \
	bfd_sprintf_vma(bfd, buffer, (bfd_vma) val)

#endif // X_DEP_H_
