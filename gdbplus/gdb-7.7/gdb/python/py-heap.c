/*
 * py-heap.c
 *
 *  Created on: March 20, 2013
 *      Author: myan
 */

#include "defs.h"
#include "gdb_assert.h"
#include "python.h"

#ifdef HAVE_PYTHON

#include "python-internal.h"
#include "heap.h"

typedef struct heap_block_object {
	PyObject_HEAD
	PyObject *address;
	PyObject *size;
	PyObject *inuse;
} heap_block_object;

/* Called by the Python interpreter when deallocating a value object.  */
static void
heap_block_dealloc (PyObject *obj)
{
	heap_block_object* self = (heap_block_object*) obj;
	Py_CLEAR(self->address);
	Py_CLEAR(self->size);
	Py_CLEAR(self->inuse);
	self->ob_type->tp_free (self);
}

/* Called when a new gdb.Heap_block object needs to be allocated.  Returns NULL on
 error, with a python exception set.  */
static PyObject *
heap_block_new (PyTypeObject *type, PyObject *args, PyObject *keywords)
{
	heap_block_object *self = NULL;
	PyObject *obj;
	struct heap_block blk;
	address_t addr = 0;

	if (PyTuple_Size (args) != 1)
	{
		PyErr_SetString (PyExc_TypeError, _("Heap_block object creation takes one argument"));
		return NULL;
	}

	//value = convert_value_from_python (PyTuple_GetItem (args, 0));
	obj = PyTuple_GetItem (args, 0);
	gdb_assert (obj != NULL);
	if (PyInt_Check (obj))
		addr = (address_t) PyInt_AsLong (obj);
	else if (PyLong_Check (obj))
		addr = (address_t) PyLong_AsLong (obj);
	else if (gdbpy_is_string (obj))
	{
		char *s;

		s = python_string_to_target_string (obj);
		if (s != NULL)
			addr = parse_and_eval_address (s);
	}

	if (!update_memory_segments_and_heaps())
	{
		PyErr_SetString (PyExc_MemoryError, _("Failed to read and initialize process's heap segments."));
		return NULL;
	}

	if (addr && get_heap_block_info(addr, &blk) )
	{
		self = (heap_block_object *)type->tp_alloc(type, 1);
		if (self == NULL)
		{
			PyErr_SetString (PyExc_MemoryError, _("Could not allocate memory to create heap_block object."));
			return NULL;
		}

		self->address = Py_BuildValue("l", blk.addr);
		self->size = Py_BuildValue("l", blk.size);
		self->inuse = Py_BuildValue("b", blk.inuse);
	}
	else
	{
		PyErr_SetString (PyExc_ValueError, _("The input address doesn't belong to any heap block."));
		return NULL;
	}

	return (PyObject *) self;
}

/* Called by the Python interpreter to obtain string representation
 of the object.  */
static PyObject *
heap_block_object_str (PyObject *obj)
{
	heap_block_object* self = (heap_block_object*) obj;
	PyObject *args, *result;
	static PyObject *format = NULL;

	if (format == NULL)
	{
		format = PyString_FromString("heap block addr=0x%lx size=%ld inuse=%d");
		if (format == NULL)
			return NULL;
	}
	args = Py_BuildValue("(OOO)", self->address, self->size, self->inuse);
	if (args == NULL)
		return NULL;

	result = PyString_Format(format, args);
	Py_DECREF(args);

	return result;
}

static PyObject *
heap_block_get_address (PyObject *self, void *closure)
{
  heap_block_object *blk_obj = (heap_block_object *) self;

  Py_INCREF (blk_obj->address);

  return blk_obj->address;
}

static PyObject *
heap_block_get_size (PyObject *self, void *closure)
{
  heap_block_object *blk_obj = (heap_block_object *) self;

  Py_INCREF (blk_obj->size);

  return blk_obj->size;
}

static PyObject *
heap_block_get_inuse (PyObject *self, void *closure)
{
  heap_block_object *blk_obj = (heap_block_object *) self;

  Py_INCREF (blk_obj->inuse);

  return blk_obj->inuse;
}

int
gdbpy_initialize_heap_block (void)
{
	if (PyType_Ready (&heap_block_object_type) < 0)
		return -1;

	Py_INCREF (&heap_block_object_type);
	PyModule_AddObject (gdb_module, "Heap_block", (PyObject *) &heap_block_object_type);

	return 0;
}

static PyGetSetDef heap_block_object_getset[] = {
  { "address", heap_block_get_address, NULL, "The starting address of the heap block.", NULL },
  { "size", heap_block_get_size, NULL, "The size of the heap block.", NULL },
  { "inuse", heap_block_get_inuse, NULL, "The inuse/free status of the heap block.", NULL },
  {NULL}  /* Sentinel */
};

PyTypeObject heap_block_object_type = {
	PyObject_HEAD_INIT (NULL)
	0, /*ob_size*/
	"gdb.Heap_block", /*tp_name*/
	sizeof (heap_block_object), /*tp_basicsize*/
	0, /*tp_itemsize*/
	heap_block_dealloc, /*tp_dealloc*/
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
	heap_block_object_str, /*tp_str*/
	0, /*tp_getattro*/
	0, /*tp_setattro*/
	0, /*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT, /*tp_flags*/
	"GDB heap memory block object", /* tp_doc */
	0, /* tp_traverse */
	0, /* tp_clear */
	0, /* tp_richcompare */
	0, /* tp_weaklistoffset */
	0, /* tp_iter */
	0, /* tp_iternext */
	0, /* tp_methods */
	0, /* tp_members */
	heap_block_object_getset, /* tp_getset */
	0, /* tp_base */
	0, /* tp_dict */
	0, /* tp_descr_get */
	0, /* tp_descr_set */
	0, /* tp_dictoffset */
	0, /* tp_init */
	0, /* tp_alloc */
	heap_block_new /* tp_new */
};

/* Implementation of gdb.heap_walk()
 * Take one argument of long or gdb.Heap_block, or no argument
   Returns the next heap block after the given address, or None.  */
PyObject *gdbpy_heap_walk (PyObject *self, PyObject *args)
{
	PyObject *result = NULL;
	struct heap_block blk;
	address_t addr = 0;
	int input_prev_block = 0;

	if (PyTuple_Size (args) == 0)
		addr = 0;
	else if (PyTuple_Size (args) == 1)
	{
		PyObject *obj = PyTuple_GetItem (args, 0);
		if (PyInt_Check (obj))
			addr = (address_t) PyInt_AsLong (obj);
		else if (PyLong_Check (obj))
			addr = (address_t) PyLong_AsLong (obj);
		else if (PyObject_TypeCheck(obj, &heap_block_object_type))
		{
			PyObject *addr_obj = ((heap_block_object*)obj)->address;
			input_prev_block = 1;
			if (PyLong_Check (addr_obj))
				addr = (address_t) PyLong_AsLong (addr_obj);
			else if (PyInt_Check (addr_obj))
				addr = (address_t) PyInt_AsLong (addr_obj);
			else
			{
				PyErr_SetString (PyExc_TypeError, _("Expect long of gdb.Heap_block's address field."));
				return NULL;
			}
		}
	}
	else
	{
		PyErr_SetString (PyExc_TypeError, _("Heap_walk takes one argument or none."));
		return NULL;
	}

	if (!input_prev_block && !update_memory_segments_and_heaps())
	{
		PyErr_SetString (PyExc_MemoryError, _("Failed to read and initialize process's heap segments."));
		return NULL;
	}

	if (get_next_heap_block (addr, &blk))
	{
		heap_block_object* blk_object;
		blk_object = PyObject_New (heap_block_object, &heap_block_object_type);
		if (blk_object)
		{
			blk_object->address = Py_BuildValue("l", blk.addr);
			blk_object->size = Py_BuildValue("l", blk.size);
			blk_object->inuse = Py_BuildValue("b", blk.inuse);
		}
		else
		{
			PyErr_SetString (PyExc_MemoryError, _("Could not allocate memory to create heap_block object."));
			return NULL;
		}
		result = (PyObject*) blk_object;
	}
	else
	{
		result = Py_None;
		Py_INCREF (Py_None);
	}

	  return result;
}

/* Implementation of gdb.big_blocks()
 * Take one argument of int/long of number of biggest heap blocks
   Returns a list of gdb.Heap_block objects  */
PyObject *gdbpy_big_blocks (PyObject *self, PyObject *args)
{
	PyObject *result = NULL;
	unsigned int n = 0;
	struct heap_block* blocks;

	if (PyTuple_Size (args) == 1)
	{
		PyObject *obj = PyTuple_GetItem (args, 0);
		if (PyInt_Check (obj))
			n = (unsigned int) PyInt_AsLong (obj);
		else
		{
			PyErr_SetString (PyExc_TypeError, _("Expect an integer of big heap blocks."));
			return NULL;
		}
	}
	else
	{
		PyErr_SetString (PyExc_TypeError, _("big_blocks takes one argument."));
		return NULL;
	}

	if (n == 0)
	{
		result = Py_None;
		Py_INCREF (Py_None);
		return result;
	}
	else if (n > 1024)
	{
		PyErr_SetString (PyExc_ValueError, _("Currently the function supports up to 1024."));
		return NULL;
	}

	if (!update_memory_segments_and_heaps())
	{
		PyErr_SetString (PyExc_MemoryError, _("Failed to read and initialize process's heap segments."));
		return NULL;
	}

	// now ask heap manager
	blocks = (struct heap_block*) malloc (sizeof(struct heap_block) * n);
	if (!blocks)
	{
		PyErr_SetString (PyExc_MemoryError, _("Could not allocate memory."));
		return NULL;
	}
	memset(blocks, 0, sizeof(struct heap_block) * n);
	if (get_biggest_blocks (blocks, n))
	{
		result = PyList_New(n);
		if (result)
		{
			unsigned int i;
			for (i = 0; i < n && blocks[i].addr; i++)
			{
				heap_block_object* blk_object;
				blk_object = PyObject_New (heap_block_object, &heap_block_object_type);
				if (blk_object)
				{
					blk_object->address = Py_BuildValue("l", blocks[i].addr);
					blk_object->size = Py_BuildValue("l", blocks[i].size);
					blk_object->inuse = Py_BuildValue("b", blocks[i].inuse);
					PyList_SET_ITEM(result, i, (PyObject*)blk_object);
				}
				else
				{
					PyErr_SetString (PyExc_MemoryError, _("Could not allocate memory to create heap_block object."));
					return NULL;
				}
			}
			// if there are not so many blocks
			while (i < n)
			{
				PyList_SET_ITEM(result, i, Py_None);
				Py_INCREF (Py_None);
				i++;
			}
		}
	}
	// cleanup
	free (blocks);

	return result;
}

#endif /* HAVE_PYTHON */
