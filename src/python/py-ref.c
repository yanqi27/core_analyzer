/*
 * py-ref.c
 *
 *  Created on: March 27, 2013
 *      Author: myan
 */

#include "defs.h"
#include "gdbsupport/gdb_assert.h"
#include "python.h"

#include "python-internal.h"
#include "ref.h"
#include "search.h"
#include "segment.h"
#include "stl_container.h"

extern PyTypeObject object_ref_type
    CPYCHECKER_TYPE_OBJECT_FOR_TYPEDEF ("object_ref");

typedef struct object_ref {
	PyObject_HEAD
	struct object_reference ref;
	//struct symbol* sym;
} object_ref;

/* This is used to initialize various gdb.REF_TYPE_ constants.  */
struct pyref_type
{
	enum storage_type type;
	const char *name;
};

#define ENTRY(X) { X, #X }

static struct pyref_type pyref_types[] =
{
	ENTRY (ENUM_UNKNOWN),
	ENTRY (ENUM_REGISTER),
	ENTRY (ENUM_STACK),
	ENTRY (ENUM_MODULE_TEXT),
	ENTRY (ENUM_MODULE_DATA),
	ENTRY (ENUM_HEAP),
	ENTRY (ENUM_ALL),
	{ (enum storage_type)0, NULL }
};

/* Return the storage type.  */
static PyObject *
object_ref_get_storage_type (PyObject *self, void *closure)
{
	object_ref *obj_ref = (object_ref *) self;

	return PyInt_FromLong (obj_ref->ref.storage_type);
}

/* Return the address of the input  */
static PyObject *
object_ref_get_address (PyObject *self, void *closure)
{
	object_ref *obj_ref = (object_ref *) self;

	return PyLong_FromLong (obj_ref->ref.vaddr);
}

/* Return the referenced address  */
static PyObject *
object_ref_get_target (PyObject *self, void *closure)
{
	object_ref *obj_ref = (object_ref *) self;

	return PyLong_FromLong (obj_ref->ref.value);
}

/* Return thread id for register/stack, none for other  */
static PyObject *
object_ref_get_tid (PyObject *self, void *closure)
{
	object_ref *obj_ref = (object_ref *) self;
	if (obj_ref->ref.storage_type == ENUM_REGISTER || obj_ref->ref.storage_type == ENUM_STACK)
		return PyInt_FromLong (obj_ref->ref.where.stack.tid);
	else
	{
		Py_INCREF (Py_None);
		return Py_None;
	}
}

/* Return register name for register, none for other  */
static PyObject *
object_ref_get_register_name (PyObject *self, void *closure)
{
	object_ref *obj_ref = (object_ref *) self;
	if (obj_ref->ref.storage_type == ENUM_REGISTER)
	{
		const char* reg_name;
		if (!obj_ref->ref.where.reg.name)
		{
			struct gdbarch *gdbarch = get_current_arch();
			reg_name = gdbarch_register_name (gdbarch, obj_ref->ref.where.reg.reg_num);
		}
		else
			reg_name = obj_ref->ref.where.reg.name;
		return PyString_FromString (reg_name);
	}
	else
	{
		Py_INCREF (Py_None);
		return Py_None;
	}
}

/* Return frame number for stack, none for other  */
static PyObject *
object_ref_get_frame (PyObject *self, void *closure)
{
	object_ref *obj_ref = (object_ref *) self;
	if (obj_ref->ref.storage_type == ENUM_STACK)
		return PyInt_FromLong (obj_ref->ref.where.stack.frame);
	else
	{
		Py_INCREF (Py_None);
		return Py_None;
	}
}

/* Return module name for global, none for other  */
static PyObject *
object_ref_get_module_name (PyObject *self, void *closure)
{
	object_ref *obj_ref = (object_ref *) self;
	if (obj_ref->ref.storage_type == ENUM_MODULE_TEXT || obj_ref->ref.storage_type == ENUM_MODULE_DATA)
		return PyString_FromString (obj_ref->ref.where.module.name);
	else
	{
		Py_INCREF (Py_None);
		return Py_None;
	}
}

/* Return gdb.Symbol for stack/global, none for other  */
static PyObject *
object_ref_get_symbol (PyObject *self, void *closure)
{
	object_ref *obj_ref = (object_ref *) self;
	struct symbol* sym = NULL;

	if (obj_ref->ref.storage_type == ENUM_STACK)
		sym = get_stack_sym(&obj_ref->ref, NULL, NULL);
	else if (obj_ref->ref.storage_type == ENUM_MODULE_TEXT || obj_ref->ref.storage_type == ENUM_MODULE_DATA)
		sym = get_global_sym(&obj_ref->ref, NULL, NULL);
	if (sym)
		return symbol_to_symbol_object(sym);
	else
	{
		Py_INCREF (Py_None);
		return Py_None;
	}
}

/* Return heap block address for heap, none for other  */
static PyObject *
object_ref_get_heap_addr (PyObject *self, void *closure)
{
	object_ref *obj_ref = (object_ref *) self;
	if (obj_ref->ref.storage_type == ENUM_HEAP)
		return PyLong_FromLong (obj_ref->ref.where.heap.addr);
	else
	{
		Py_INCREF (Py_None);
		return Py_None;
	}
}

/* Return heap block size for heap, none for other  */
static PyObject *
object_ref_get_heap_size (PyObject *self, void *closure)
{
	object_ref *obj_ref = (object_ref *) self;
	if (obj_ref->ref.storage_type == ENUM_HEAP)
		return PyLong_FromLong (obj_ref->ref.where.heap.size);
	else
	{
		Py_INCREF (Py_None);
		return Py_None;
	}
}

/* Return heap block inuse for heap, none for other  */
static PyObject *
object_ref_get_heap_inuse (PyObject *self, void *closure)
{
	object_ref *obj_ref = (object_ref *) self;
	if (obj_ref->ref.storage_type == ENUM_HEAP)
		return PyInt_FromLong (obj_ref->ref.where.heap.inuse);
	else
	{
		Py_INCREF (Py_None);
		return Py_None;
	}
}

/* Return gdb.Type for heap, none for other  */
static PyObject *
object_ref_get_type (PyObject *self, void *closure)
{
	object_ref *obj_ref = (object_ref *) self;
	struct type* type = NULL;

	if (obj_ref->ref.storage_type == ENUM_HEAP)
		type = get_heap_object_type(&obj_ref->ref);

	if (type)
		return type_to_type_object(type);
	else
	{
		Py_INCREF (Py_None);
		return Py_None;
	}
}

/* Called by the Python interpreter when deallocating a value object.  */
static void
object_ref_dealloc (PyObject *obj)
{
	object_ref* self = (object_ref*) obj;
	Py_TYPE (self)->tp_free (self);
}

/* Called when a new gdb.Object_ref object needs to be allocated.  Returns NULL on
 error, with a python exception set.  */
static PyObject *
object_ref_new (PyTypeObject *type, PyObject *args, PyObject *keywords)
{
	object_ref *self = NULL;
	PyObject *obj;
	address_t addr = 0;

	if (PyTuple_Size (args) != 1)
	{
		PyErr_SetString (PyExc_TypeError, _("Object_ref object creation takes one argument"));
		return NULL;
	}

	obj = PyTuple_GetItem (args, 0);
	gdb_assert (obj != NULL);
	if (PyInt_Check (obj))
		addr = (address_t) PyInt_AsLong (obj);
	else if (gdbpy_is_string (obj))
	{
		gdb::unique_xmalloc_ptr<char> s
			= python_string_to_target_string (obj);
		if (s != NULL)
			addr = parse_and_eval_address (s.get());
	}

	if (!update_memory_segments_and_heaps())
	{
		PyErr_SetString (PyExc_MemoryError, _("Failed to read and initialize process's heap segments."));
		return NULL;
	}

	if (addr)
	{
		self = (object_ref *)type->tp_alloc(type, 1);
		if (self == NULL)
		{
			PyErr_SetString (PyExc_MemoryError, _("Could not allocate memory to create object_ref object."));
			return NULL;
		}

		self->ref.level        = 0;
		self->ref.target_index = -1;
		self->ref.storage_type = ENUM_UNKNOWN;
		self->ref.vaddr        = addr;
		self->ref.value        = 0;
		self->ref.where.target.size = 1;
		fill_ref_location(&self->ref);
	}
	else
	{
		PyErr_SetString (PyExc_ValueError, _("The input address is 0."));
		return NULL;
	}

	return (PyObject *) self;
}

/* Called by the Python interpreter to obtain string representation
 of the object.  */
static PyObject *
object_ref_str (PyObject *obj)
{
	object_ref* self = (object_ref*) obj;
	PyObject *args = NULL, *result = NULL;
	PyObject *format = NULL;

	struct symbol* sym;
	address_t sym_addr;
	size_t    sym_size;
	const char* sym_name;

	if (self->ref.storage_type == ENUM_REGISTER)
	{
		const char* reg_name;
		if (!self->ref.where.reg.name)
		{
			struct gdbarch *gdbarch = get_current_arch();
			reg_name = gdbarch_register_name (gdbarch, self->ref.where.reg.reg_num);
		}
		else
			reg_name = self->ref.where.reg.name;
		format = PyString_FromString("[register] thread %d %s=0x%lx");
		args = Py_BuildValue("(isl)", self->ref.where.reg.tid, reg_name, self->ref.value);
	}
	else if (self->ref.storage_type == ENUM_STACK)
	{
		sym = get_stack_sym(&self->ref, &sym_addr, &sym_size);
		if (sym)
			sym_name = sym->natural_name();
		else
		{
			sym_name = "";
			sym_addr = self->ref.vaddr;
		}
		format = PyString_FromString("[stack] thread %d  frame %d %s");
		args = Py_BuildValue("(iis)", self->ref.where.stack.tid, self->ref.where.stack.frame, sym_name);
	}
	else if (self->ref.storage_type == ENUM_MODULE_TEXT || self->ref.storage_type == ENUM_MODULE_DATA)
	{
		sym = get_global_sym(&self->ref, &sym_addr, &sym_size);
		if (sym)
			sym_name = sym->natural_name();
		else
		{
			sym_name = "unknown";
			sym_addr = self->ref.vaddr;
		}
		format = PyString_FromString("[.text/.data] %s %s");
		args = Py_BuildValue("(ss)", self->ref.where.module.name, sym_name);
	}
	else if (self->ref.storage_type == ENUM_HEAP)
	{
		if (self->ref.where.heap.inuse)
		{
			struct type* type = get_heap_object_type(&self->ref);
			const char* type_name = TYPE_SAFE_NAME(type);
			format = PyString_FromString("[heap block] 0x%lx--0x%lx size=%ld (type=\"%s\")");
			args = Py_BuildValue("(llls)", self->ref.where.heap.addr,
							self->ref.where.heap.addr + self->ref.where.heap.size,
							self->ref.where.heap.size, type_name);
		}
		else
		{
			format = PyString_FromString("[heap block] 0x%lx--0x%lx size=%ld free");
			args = Py_BuildValue("(lll)", self->ref.where.heap.addr,
							self->ref.where.heap.addr + self->ref.where.heap.size,
							self->ref.where.heap.size);
		}
	}
	else
	{
		format = PyString_FromString("[unknown] 0x%lx");
		args = Py_BuildValue("(l)", self->ref.vaddr);
	}

	if (self->ref.target_index >= 0 && self->ref.value && format && args)
	{
		PyObject* target_format = PyString_FromString(" 0x%lx: 0x%lx");
		int pos = PyTuple_Size(args);

		PyUnicode_Concat(format, target_format);
		if (_PyTuple_Resize(&args, pos+2) == 0)
		{
			PyTuple_SET_ITEM(args, pos, Py_BuildValue("l", self->ref.vaddr));
			PyTuple_SET_ITEM(args, pos+1, Py_BuildValue("l", self->ref.value));
		}
		Py_DECREF(target_format);
	}

	if (format == NULL || args == NULL)
		return NULL;
	else
		result = PyUnicode_Format(format, args);
	Py_DECREF(format);
	Py_DECREF(args);

	return result;
}

int
gdbpy_initialize_object_ref (void)
{
	int i;

	if (PyType_Ready (&object_ref_type) < 0)
		return -1;

	for (i = 0; pyref_types[i].name; ++i)
	{
		if (PyModule_AddIntConstant (gdb_module, (char *) pyref_types[i].name, pyref_types[i].type) < 0)
			return -1;
	}

	Py_INCREF (&object_ref_type);
	PyModule_AddObject (gdb_module, "Object_ref", (PyObject *) &object_ref_type);

	return 0;
}

static gdb_PyGetSetDef object_ref_getset[] = {
  { "storage_type", object_ref_get_storage_type, NULL, "The storage class that address belongs to", NULL },
  { "address", object_ref_get_address, NULL, "The reference address", NULL },
  { "target", object_ref_get_target, NULL, "The referenced target", NULL },
  { "tid", object_ref_get_tid, NULL, "The thread id that the object belongs to", NULL },
  { "register_name", object_ref_get_register_name, NULL, "The register name of the reference", NULL },
  { "frame", object_ref_get_frame, NULL, "The frame number of the stack reference", NULL },
  { "module_name", object_ref_get_module_name, NULL, "The module name that the object belongs to", NULL },
  { "symbol", object_ref_get_symbol, NULL, "The symbol associated with the object", NULL },
  { "heap_addr", object_ref_get_heap_addr, NULL, "The address of the heap block of the object", NULL },
  { "heap_size", object_ref_get_heap_size, NULL, "The size of the heap block of the object", NULL },
  { "heap_inuse", object_ref_get_heap_inuse, NULL, "The inuse flag of the heap block of the object", NULL },
  { "type", object_ref_get_type, NULL, "The type associated with the heap object", NULL },
  {NULL}  /* Sentinel */
};

PyTypeObject object_ref_type = {
	PyVarObject_HEAD_INIT (NULL, 0)
	"gdb.Object_ref", /*tp_name*/
	sizeof (object_ref), /*tp_basicsize*/
	0, /*tp_itemsize*/
	object_ref_dealloc, /*tp_dealloc*/
	0, /*tp_print*/
	0, /*tp_getattr*/
	0, /*tp_setattr*/
	0, /*tp_compare*/
	0, /*tp_repr*/
	0, /*tp_as_number*/
	0, /*tp_as_sequence*/
	0, /*tp_as_mapping*/
	0, /*tp_hash*/
	0, /*tp_call*/
	object_ref_str, /*tp_str*/
	0, /*tp_getattro*/
	0, /*tp_setattro*/
	0, /*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT, /*tp_flags*/
	"GDB object reference", /* tp_doc */
	0, /* tp_traverse */
	0, /* tp_clear */
	0, /* tp_richcompare */
	0, /* tp_weaklistoffset */
	0, /* tp_iter */
	0, /* tp_iternext */
	0, /* tp_methods */
	0, /* tp_members */
	object_ref_getset, /* tp_getset */
	0, /* tp_base */
	0, /* tp_dict */
	0, /* tp_descr_get */
	0, /* tp_descr_set */
	0, /* tp_dictoffset */
	0, /* tp_init */
	0, /* tp_alloc */
	object_ref_new /* tp_new */
};

/* Implementation of gdb.cpp_object()
 * Take one argument of an expression that may be evaluated to a C++ type
   Returns a list of gdb.Object_ref objects  */
PyObject *gdbpy_cpp_object (PyObject *self, PyObject *args)
{
	PyObject *result = NULL;
	gdb::unique_xmalloc_ptr<char> exp;
	struct CA_LIST* objects;

	// Get the input parameters
	if (PyTuple_Size (args) == 1)
	{
		PyObject *obj = PyTuple_GetItem (args, 0);
		if (gdbpy_is_string (obj))
			exp = python_string_to_target_string (obj);
		else
		{
			PyErr_SetString (PyExc_TypeError, _("Expect an integer of big heap blocks."));
			return NULL;
		}
	}
	else
	{
		PyErr_SetString (PyExc_TypeError, _("This function takes one argument."));
		return NULL;
	}

	// Make sure we have built necessary data structures to do searching
	if (!update_memory_segments_and_heaps())
	{
		PyErr_SetString (PyExc_MemoryError, _("Failed to read and initialize process's heap segments."));
		return NULL;
	}

	// Search for the objects
	objects = search_cplusplus_objects_with_vptr (exp.get());
	if (objects)
	{
		struct object_reference* ref;
		unsigned int n = ca_list_size(objects);
		unsigned int i;

		result = PyList_New(n);

		i = 0;
		ca_list_traverse_start(objects);
		while ( (ref = (struct object_reference*) ca_list_traverse_next(objects)) )
		{
			object_ref* obj_ref = PyObject_New (object_ref, &object_ref_type);
			obj_ref->ref = *ref;
			PyList_SET_ITEM(result, i, (PyObject*)obj_ref);
			i++;

			free (ref);
		}
		ca_list_delete (objects);
	}
	else
	{
		Py_INCREF (Py_None);
		result = Py_None;
	}

	return result;
}

/* Implementation of gdb.shared_object()
 * Take any number of thread id as input
   Returns a list of gdb.Object_ref objects which are shared by the input threads and the other */
PyObject *gdbpy_shared_object (PyObject *self, PyObject *args)
{
	PyObject *result = NULL;
	struct CA_LIST* threads;
	struct CA_LIST* objects;
	int* ptid;
	int i;

	// Make sure we have built necessary data structures to do searching
	if (!update_memory_segments_and_heaps())
	{
		PyErr_SetString (PyExc_MemoryError, _("Failed to read and initialize process's heap segments."));
		return NULL;
	}

	threads = ca_list_new();
	// Get the input parameters
	for (i = 0; i< PyTuple_Size (args); i++)
	{
		PyObject *obj = PyTuple_GetItem (args, i);
		if (PyInt_Check (obj))
		{
			int tid = PyInt_AsLong (obj);
			unsigned int index;
			struct ca_segment* segment;
			int valid_tid = 0;

			for (index=0; index<g_segment_count; index++)
			{
				segment = &g_segments[index];
				if (segment->m_type == ENUM_STACK && segment->m_thread.tid == tid)
				{
					valid_tid = 1;
					break;
				}
			}

			if (valid_tid)
			{
				ptid = (int*) malloc(sizeof(int));
				*ptid = tid;
				ca_list_push_front(threads, ptid);
			}
			else
			{
				PyErr_SetString (PyExc_TypeError, _("Input thread id is invalid."));
				return NULL;
			}
		}
		else
		{
			PyErr_SetString (PyExc_TypeError, _("Expect an integer of thread id."));
			return NULL;
		}
	}

	// Search for the objects
	objects = search_shared_objects_by_threads(threads);
	if (objects)
	{
		struct object_reference* ref;
		unsigned int n = ca_list_size(objects);

		result = PyList_New(n);

		i = 0;
		ca_list_traverse_start(objects);
		while ( (ref = (struct object_reference*) ca_list_traverse_next(objects)) )
		{
			object_ref* obj_ref = PyObject_New (object_ref, &object_ref_type);
			obj_ref->ref = *ref;
			PyList_SET_ITEM(result, i, (PyObject*)obj_ref);
			i++;

			free (ref);
		}
		ca_list_delete (objects);
	}
	else
	{
		Py_INCREF (Py_None);
		result = Py_None;
	}

	// clean up
	ca_list_traverse_start(threads);
	while ( (ptid = (int*) ca_list_traverse_next(threads)))
		free (ptid);
	ca_list_delete(threads);

	return result;
}

/*
 * Implementation of gdb.ref()
 * Take at least one argument: object address
 *   2nd argument: object size
 *   3rd argument: search scope
 * Returns a list of gdb.Object_ref objects
 */
PyObject *gdbpy_objref (PyObject *self, PyObject *args)
{
	PyObject *result = NULL;
	address_t obj_addr = 0;
	size_t    obj_size = 1;
	struct CA_LIST* refs;
	int num_args = PyTuple_Size (args);
	PyObject *obj;
	enum storage_type stype = ENUM_UNKNOWN;

	// Get the input arguments
	if (num_args < 1 || num_args > 3)
	{
		PyErr_SetString (PyExc_TypeError, _("The function takes at least one argument and three arguments in most: object address, size and scope."));
		return NULL;
	}

	// The 1st argument is object address
	obj = PyTuple_GetItem (args, 0);
	if (PyInt_Check (obj))
		obj_addr = (address_t) PyInt_AsLong (obj);
	else
	{
		PyErr_SetString (PyExc_TypeError, _("Expect an integer of object address as the first parameter"));
		return NULL;
	}
	// 2nd argument is the object size
	if (num_args >= 2)
	{
		obj = PyTuple_GetItem (args, 1);
		if (PyInt_Check (obj))
			obj_size = (address_t) PyInt_AsLong (obj);
		else
		{
			PyErr_SetString (PyExc_TypeError, _("Expect an integer of object size as the second parameter"));
			return NULL;
		}
	}
	// 3rd argument is the searching scope
	if (num_args == 3)
	{
		obj = PyTuple_GetItem (args, 2);
		if (PyInt_Check (obj))
			stype = (enum storage_type) PyInt_AsLong (obj);
		else
		{
			PyErr_SetString (PyExc_TypeError, _("Expect an integer of search scope for the third parameter"));
			return NULL;
		}
	}

	// Make sure we have built necessary data structures to do searching
	if (!update_memory_segments_and_heaps())
	{
		PyErr_SetString (PyExc_MemoryError, _("Failed to read and initialize process's heap segments."));
		return NULL;
	}

	// Search for the references
	refs = search_object_refs (obj_addr, obj_size, 1, stype);
	if (refs)
	{
		struct object_reference* ref;
		unsigned int n = ca_list_size(refs);
		unsigned int i;

		result = PyList_New(n);

		i = 0;
		ca_list_traverse_start(refs);
		while ( (ref = (struct object_reference*) ca_list_traverse_next(refs)) )
		{
			object_ref* obj_ref = PyObject_New (object_ref, &object_ref_type);
			obj_ref->ref = *ref;
			PyList_SET_ITEM(result, i, (PyObject*)obj_ref);
			i++;

			free (ref);
		}
		// caller is responsible to release the returned list
		ca_list_delete (refs);
	}
	else
	{
		Py_INCREF (Py_None);
		result = Py_None;
	}

	return result;
}

PyObject *gdbpy_global_and_static_symbols (PyObject *self, PyObject *args)
{
	gdbpy_ref<> return_list (PyList_New (0));
	if (return_list == NULL)
		return NULL;

	global_symbol_searcher spec (VARIABLES_DOMAIN, ".*");
	SCOPE_EXIT {
		for (const char *elem : spec.filenames)
		xfree ((void *) elem);
	};
	std::vector<symbol_search> symbols = spec.search ();
	for (const symbol_search &p : symbols) {
		if (p.block != GLOBAL_BLOCK && p.block != STATIC_BLOCK)
			continue;
		if (p.symbol == NULL)
			continue;
		PyObject *sym_obj = symbol_to_symbol_object (p.symbol);
		if (PyList_Append (return_list.get (), sym_obj) == -1)
			return NULL;
    }

	return return_list.release ();
}
