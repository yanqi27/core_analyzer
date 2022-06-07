import gdb
import os
import sys

class Block:
	def __init__(self, address, size, inuse):
		self.address = address
		self.size = size
		self.inuse = inuse

# Test heap_block API
def check_heap_blocks(known_blks, count):
	print("[ca_test] Checking heap blocks ...")
	ulong_type = gdb.lookup_type('long')
	user_blks = []
	i = 0
	while i < count:
		blk = known_blks + i
		if not blk:
			raise Exception('block[%d] is unexpectedly NIL' % i)
		blk_addr = int(blk['p'].cast(ulong_type))
		blk_size = int(blk['size'].cast(ulong_type))
		my_blk = gdb.heap_block(blk_addr)
		if not my_blk:
			raise Exception('Failed to query block at 0x%x' % blk_addr)
		match = True
		if blk['inuse']:
			if blk_addr != my_blk.address or blk_size != my_blk.size or not my_blk.inuse:
				match = False
			py_blk = Block(blk_addr, blk_size, True)
			user_blks.append(py_blk)
		else:
			if my_blk.inuse:
				match = False

		if not match:
			print("[ca_test] core analyzer returns wrong heap info of block [%d]" % (i))
			print("[ca_test] \texpected:  addr=0x%x size=%u inuse=%d" \
				% (blk_addr, blk_size, blk['inuse']))
			print("[ca_test] \tgot:       addr=0x%x size=%u inuse=%d" \
				% (my_blk.address, my_blk.size, my_blk.inuse))
			raise Exception('Failed to check block at 0x%x' % blk_addr)

		i = i + 1
	print("[ca_test]\tVerified %d heap blocks" % (count))
	return user_blks

# Test biggest n blocks
def check_big_blocks(big_blks, big_count, user_blks):
	print("[ca_test] Checking biggest heap blocks ...")
	sorted_user_blks = sorted(user_blks, key = lambda Block: Block.size, reverse = True)
	i = 0
	while i < big_count:
		blk = big_blks[i]
		blk_addr = blk.address
		blk_size = blk.size
		if blk_size != sorted_user_blks[i].size:
			print("[ca_test] The [%d]th biggest heap block is wrong" % (i + 1))
			print("[ca_test] expected:  addr=0x%x size=%u" \
				% (sorted_user_blks[i].address, sorted_user_blks[i].size))
			print("[ca_test] got:       addr=0x%x size=%u" % (blk_addr, blk_size))
			raise Exception('Test Failed')

		i = i + 1
	print("[ca_test]\tFound top %d biggest heap blocks" % (big_count))
	big_blks = []
	sorted_user_blks = []

# Test heap walk
def check_heap_walk(user_blks):
	print("[ca_test] Checking heap walk ...")
	inuse_blks = {}
	blk = gdb.heap_walk(0)
	inuse_count = 0
	free_count = 0
	while blk:
		if blk.inuse:
			inuse_blks[blk.address] = blk
			inuse_count = inuse_count + 1
		else:
			free_count = free_count + 1
		blk = gdb.heap_walk(blk)
	for blk in user_blks:
		if blk.address not in inuse_blks:
			print("[ca_test] Heap walk misses in-use block: addr=0x%x size=%u" \
				% (blk.address, blk.size))
			raise Exception('Test Failed')
	print("[ca_test]\tHeapwalk discovered %d in-use blocks and %d free blocks" \
		% (inuse_count, free_count))
	inuse_blks = []

# Test C++ objects
def check_cplusplus_object(class_name, object_count):
	print("[ca_test] Checking C++ objects ...")
	objects = gdb.cpp_object(class_name)
	if len(objects) != object_count:
		print("[ca_test] Expecting %d \"Derived\" objects" % (object_count))
		print("[ca_test] Actually found %d \"Derived\" objects" % (len(objects)))
		raise Exception('Test Failed')
	print("[ca_test]\tFound %d \"Derived\" objects" % (len(objects)))
	objects = []

# Test reference tracing
def check_ref():
	print("[ca_test] Checking object reference ...")
	ulong_type = gdb.lookup_type('long')
	var_hidden_object = gdb.parse_and_eval("hidden_object")
	var_addr = int(var_hidden_object.address.cast(ulong_type))
	obj_addr = int(var_hidden_object)
	if obj_addr == 0:
		print("[ca_test] Object address is NULL")
		raise Exception('Test Failed')
	# "hidden_object" is a gloval variable that points to a heap object
	blk = gdb.heap_block(obj_addr)
	if blk == None or blk.address != obj_addr:
		print("[ca_test] Failed to query heap object of address 0x%x" % (obj_addr))
		raise Exception('Test Failed')
	# Search in global sections
	refs = gdb.ref(obj_addr, 1, gdb.ENUM_MODULE_TEXT | gdb.ENUM_MODULE_DATA)
	if refs == None or len(refs) != 1 or refs[0].address != var_addr:
		print("[ca_test] Failed to find the global reference (var \"hidden_object\" " \
			"at 0x%x) to object at address 0x%x" % (var_addr, obj_addr))
		raise Exception('Test Failed')
	print("[ca_test]\tFound the global reference: var \"hidden_object\" " \
		"at 0x%x" % (var_addr))
	# Search in heap
	refs = gdb.ref(obj_addr, 1, gdb.ENUM_HEAP)
	if (refs == None or not refs[0].heap_inuse):
		print("[ca_test] Failed to find the heap reference to object at address 0x%x" \
			% (obj_addr))
		raise Exception('Test Failed')
	if len(refs) != 1:
		print(("[ca_test]\tFound %d references in heap" % len(refs)))
	print("[ca_test]\tFound heap reference: addr=0x%x size=%u to object at address 0x%x" \
		% (refs[0].heap_addr, refs[0].heap_size, obj_addr))

def run_tests():
	# Retrieve global variables defined in mallocTest
	count = gdb.parse_and_eval("num_regions")
	known_blks = gdb.parse_and_eval("regions")
	big_count = int(gdb.parse_and_eval("num_big_regions"))
	object_count = int(gdb.parse_and_eval("num_derived"))
	# Tests
	user_blks = check_heap_blocks(known_blks, count)
	big_blks = gdb.big_block(big_count)
	check_big_blocks(big_blks, big_count, user_blks)
	check_heap_walk(user_blks)
	check_cplusplus_object("Derived", object_count)
	check_ref()

#
# Fun starts here
#
core_name = None
try:
	print("[ca_test] ==== Test Against Live Process ====")
	gdb.execute('break last_call')
	gdb.execute ('set confirm off')
	gdb.execute('run')
	run_tests()

	print("[ca_test] ==== Test Against Core Dump ====")
	core_name = 'core.' + str(gdb.inferiors()[0].pid)
	gdb.execute ('gcore ' + core_name)
	gdb.execute ('kill')
	gdb.execute ('core ' + core_name)
	run_tests()

	print("[ca_test] Pass")
except Exception as e:
	print(("[ca_test] " + e.message))
	print("[ca_test] Test failed")
	if core_name and os.path.isfile(core_name):
		os.unlink(core_name)
	gdb.execute ('quit 1')
finally:
	if core_name and os.path.isfile(core_name):
		os.unlink(core_name)
gdb.execute ('quit')
