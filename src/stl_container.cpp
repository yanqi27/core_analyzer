/*
 * stl_container.cpp
 * 		A wrapper of stl tree/vector/list etc. because gdb is a c program
 */
#include "stl_container.h"


/*
 * Implementations
 * 		C++ uses compiler STL routines
 * 		C   uses mimic code
 */
#ifdef __cplusplus

#include <set>
#include <list>

/*
 * SET
 */
struct CA_SET
{
	std::set<void*,CA_CompareFunctionType>* m_set;
	std::set<void*,CA_CompareFunctionType>::iterator m_itr;
	CA_SET(CA_CompareFunctionType comp)
	{
		m_set = new std::set<void*,CA_CompareFunctionType> (comp);
		m_itr  = m_set->begin();
	}
	~CA_SET()
	{
		delete m_set;
	}
};

struct CA_SET* ca_set_new(CA_CompareFunctionType comp)
{
	return new CA_SET (comp);
}

void ca_set_delete(struct CA_SET* iset)
{
	delete iset;
}

void  ca_set_clear(struct CA_SET* iset)
{
	iset->m_set->clear();
}

void* ca_set_find(struct CA_SET* iset, void* val)
{
	std::set<void*,CA_CompareFunctionType>::iterator it = iset->m_set->find(val);
	if (it != iset->m_set->end())
		return *it;
	else
		return NULL;
}

bool ca_set_insert(struct CA_SET* iset, void* val)
{
	std::pair<std::set<void*,CA_CompareFunctionType>::iterator,bool> ret;
	ret = iset->m_set->insert (val);
	if (ret.second == false)
		return false;
	else
		return true;
}

void  ca_set_traverse_start(struct CA_SET* iset)
{
	iset->m_itr = iset->m_set->begin();
}

void* ca_set_traverse_next(struct CA_SET* iset)
{
	if (iset->m_itr != iset->m_set->end())
	{
		void* result = *(iset->m_itr);
		(iset->m_itr)++;
		return result;
	}
	return NULL;
}

/*
 * LIST
 */
struct CA_LIST
{
	std::list<void*>* m_list;
	std::list<void*>::iterator m_itr;
	CA_LIST()
	{
		m_list = new std::list<void*>;
		m_itr  = m_list->begin();
	}
	~CA_LIST()
	{
		delete m_list;
	}
};

void  ca_list_traverse_start(struct CA_LIST* ilist)
{
	ilist->m_itr = ilist->m_list->begin();
}

void* ca_list_traverse_next(struct CA_LIST* ilist)
{
	void* result;
	if (ilist->m_itr != ilist->m_list->end())
	{
		result = *(ilist->m_itr);
		(ilist->m_itr)++;
	}
	else
		result = NULL;
	return result;
}

void  ca_list_clear(struct CA_LIST* ilist)
{
	ilist->m_list->clear();
}

void  ca_list_push_front(struct CA_LIST* ilist, void* val)
{
	ilist->m_list->push_front(val);
}

void  ca_list_push_back(struct CA_LIST* ilist, void* val)
{
	ilist->m_list->push_back(val);
}

void* ca_list_pop_front(struct CA_LIST* ilist)
{
	if (!ilist->m_list->empty())
	{
		void* val = ilist->m_list->front();
		ilist->m_list->pop_front();
		return val;
	}
	return NULL;
}

struct CA_LIST* ca_list_new(void)
{
	return new CA_LIST;
}

void ca_list_delete(struct CA_LIST* ilist)
{
	delete ilist;
}

bool ca_list_empty(struct CA_LIST* ilist)
{
	return ilist->m_list->empty();
}

size_t ca_list_size(struct CA_LIST* ilist)
{
	return ilist->m_list->size();
}

void* ca_list_find(struct CA_LIST* ilist, void* value)
{
	std::list<void*>::iterator it;
	for (it = ilist->m_list->begin(); it != ilist->m_list->end(); it++)
	{
		if (*it == value)
			return value;
	}
	return NULL;
}

#else

/*
 * SET
 */
#ifdef CA_USE_SPLAY_TREE
/*
 * gdb uses splay tree
 */
struct CA_SET
{
	splay_tree tree;
	splay_tree_node _itr;
};

struct CA_SET* ca_set_new(CA_CompareFunctionType comp)
{
	struct CA_SET* aset = (struct CA_SET*) malloc (sizeof(struct CA_SET));
	aset->tree = splay_tree_new(comp, NULL, NULL);
	return aset;
}

void ca_set_delete(struct CA_SET* iset)
{
	splay_tree_delete(iset->tree);
	free(iset);
}

void  ca_set_clear(struct CA_SET* iset)
{
	splay_tree_node node = splay_tree_min (iset->tree);
	while (node)
	{
		splay_tree_remove(iset->tree, node->key);
		node = splay_tree_min (iset->tree);
	}
}

void* ca_set_find(struct CA_SET* iset, void* key)
{
	splay_tree_node node = splay_tree_lookup (iset->tree, (splay_tree_key)key);
	if (!node)
		return NULL;
	else
		return (void*)node->value;
}

bool ca_set_insert_key_and_val(struct CA_SET* iset, void* key, void* val)
{
	if (!splay_tree_lookup (iset->tree, (splay_tree_key)key))
	{
		splay_tree_insert (iset->tree, (splay_tree_key)key, (splay_tree_value) val);
		return true;
	}
	else
		return false;
}

void  ca_set_traverse_start(struct CA_SET* iset)
{
	iset->_itr = splay_tree_min (iset->tree);
}

void* ca_set_traverse_next(struct CA_SET* iset)
{
	if (iset->_itr)
	{
		void* result = (void*) iset->_itr->value;
		iset->_itr = splay_tree_successor (iset->tree, iset->_itr->key);
		return result;
	}
	return NULL;
}

#else
/*
 * A temporary implementation for C client
 */
/*struct CA_SET
{
	CA_CompareFunctionType compfunc;
	size_t _size;
	struct CA_LIST_NODE* _head;
	struct CA_LIST_NODE* _itr;
};

struct CA_SET* ca_set_new(CA_CompareFunctionType comp)
{
	struct CA_SET* aset = (struct CA_SET*) malloc (sizeof(struct CA_SET));
	aset->compfunc = comp;
	aset->_size = 0;
	aset->_head = NULL;
	aset->_itr  = NULL;
	return aset;
}

void ca_set_delete(struct CA_SET* iset)
{
	ca_set_clear(iset);
	free(iset);
}

void  ca_set_clear(struct CA_SET* iset)
{
	struct CA_LIST_NODE* node = iset->_head;
	while(node)
	{
		struct CA_LIST_NODE* next_node = node->next;
		free (node);
		node = next_node;
	}
	iset->_head = NULL;
	iset->_itr  = NULL;
	iset->_size = 0;
}

void* ca_set_find(struct CA_SET* iset, void* val)
{
	struct CA_LIST_NODE* node = iset->_head;
	while (node)
	{
		if (!iset->compfunc(node->value, val) && !iset->compfunc(val, node->value))
			return node->value;
		node = node->next;
	}
	return NULL;
}

bool ca_set_insert(struct CA_SET* iset, void* val)
{
	if (!ca_set_find(iset, val))
	{
		struct CA_LIST_NODE* node = (struct CA_LIST_NODE*) malloc (sizeof(struct CA_LIST_NODE));
		node->value = val;
		node->next = iset->_head;
		iset->_head = node;
		iset->_size++;
		return true;
	}
	else
		return false;
}

void  ca_set_traverse_start(struct CA_SET* iset)
{
	iset->_itr = iset->_head;
}

void* ca_set_traverse_next(struct CA_SET* iset)
{
	if (iset->_itr)
	{
		void* result = iset->_itr->value;
		iset->_itr = iset->_itr->next;
		return result;
	}
	return NULL;
}
*/
#endif

/*
 * LIST
 */
struct CA_LIST_NODE
{
	struct CA_LIST_NODE* next;
	void* value;
};

struct CA_LIST
{
	size_t _size;
	struct CA_LIST_NODE* _head;
	struct CA_LIST_NODE* _itr;
};

void  ca_list_traverse_start(struct CA_LIST* ilist)
{
	ilist->_itr = ilist->_head;
}

void* ca_list_traverse_next(struct CA_LIST* ilist)
{
	if (ilist->_itr)
	{
		void* result = ilist->_itr->value;
		ilist->_itr = ilist->_itr->next;
		return result;
	}
	return NULL;
}

void* ca_list_find(struct CA_LIST* ilist, void* value)
{
	struct CA_LIST_NODE* node;
	for (node = ilist->_head; node; node = node->next)
	{
		if (node->value == value)
			return value;
	}
	return NULL;
}

void  ca_list_clear(struct CA_LIST* ilist)
{
	struct CA_LIST_NODE* node = ilist->_head;
	while(node)
	{
		struct CA_LIST_NODE* next_node = node->next;
		free (node);
		node = next_node;
	}
	ilist->_head = NULL;
	ilist->_itr  = NULL;
	ilist->_size = 0;
}

void  ca_list_push_front(struct CA_LIST* ilist, void* val)
{
	struct CA_LIST_NODE* node = (struct CA_LIST_NODE*) malloc (sizeof(struct CA_LIST_NODE));
	node->value = val;
	node->next = ilist->_head;
	ilist->_head = node;
	ilist->_size++;
}

void  ca_list_push_back(struct CA_LIST* ilist, void* val)
{
	struct CA_LIST_NODE* node = (struct CA_LIST_NODE*) malloc (sizeof(struct CA_LIST_NODE));
	node->value = val;
	node->next = NULL;
	if (ilist->_head)
	{
		struct CA_LIST_NODE* p;
		struct CA_LIST_NODE* tail;
		for (p=ilist->_head; p; p=p->next)
		{
			tail = p;
		}
		tail->next = node;
	}
	else
		ilist->_head = node;
	ilist->_size++;
}

void* ca_list_pop_front(struct CA_LIST* ilist)
{
	if (ilist->_head)
	{
		struct CA_LIST_NODE* node = ilist->_head;
		void* val = node->value;
		ilist->_head = ilist->_head->next;
		ilist->_size--;
		free (node);
		return val;
	}
	return NULL;
}

struct CA_LIST* ca_list_new(void)
{
	struct CA_LIST* alist = (struct CA_LIST*) malloc (sizeof(struct CA_LIST));
	alist->_size = 0;
	alist->_head = NULL;
	alist->_itr  = NULL;
	return alist;
}

void ca_list_delete(struct CA_LIST* ilist)
{
	ca_list_clear(ilist);
	free(ilist);
}

bool ca_list_empty(struct CA_LIST* ilist)
{
	return (ilist->_size <= 0);
}

size_t ca_list_size(struct CA_LIST* ilist)
{
	return ilist->_size;
}

#endif // __cplusplus
