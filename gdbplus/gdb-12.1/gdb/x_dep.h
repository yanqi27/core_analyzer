/*
 * x_dep.h
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */
#ifndef X_DEP_H_
#define X_DEP_H_

#define CA_PRINT(format,args...) \
	printf_filtered(_(format), ##args)

#include "x_common.h"
#include "gdbcmd.h"

#define ITERATE_OVER_THREADS() iterate_over_threads(thread_tcache, NULL)

#define THREAD_CB_RETURN_TYPE int
#define THREAD_CB_FUNC(info, data) thread_tcache(struct thread_info *info, void *data)
#define THREAD_CB_RETURN_CONT 0

#define CA_SYMBOL_TYPE(sym) (sym)->type()
#define CA_VALUE_TYPE(value) value_type(value)
#define CA_VALUE_ADDRESS(value) value_address(value)
#define CA_TYPE_LENGTH(type) TYPE_LENGTH(type)
#define CA_TYPE_TARGET_TYPE(type) TYPE_TARGET_TYPE(type)
#define CA_TYPE_CODE(type) (type)->code()

#define CA_LOOKUP_SYMBOL(name) lookup_symbol(name, 0, VAR_DOMAIN, 0).symbol
#define CA_LOOKUP_SYMBOL_FUNC(name) lookup_symbol(name, 0, VAR_DOMAIN, 0).symbol
#define CA_LOOKUP_GLOBAL_SYMBOL(name) lookup_global_symbol(name, 0, VAR_DOMAIN).symbol

#define CA_TCMALLOC_PAGE_MAP2 "TCMalloc_PageMap2<35>::LEAF_BITS"
#define CA_TCMALLOC_PAGE_MAP3 "TCMalloc_PageMap3<35>::LEAF_BITS"

#define CA_VFPRINTF(stream, format, args) \
	vfprintf_filtered ((ui_file *)stream, format, args)

#define CA_INIT_DISASSEMBLE_INFO(di, stream, fprintf_func, fprintf_styled_func) \
	init_disassemble_info(di, stream, fprintf_func)

#define CA_SPRINTF_VMA(bfd, buffer, val) \
	sprintf_vma(buffer, (bfd_vma) val);

enum disassembler_style
{
	dis_style_text,
	dis_style_mnemonic,
	dis_style_more
};

#endif // X_DEP_H_
