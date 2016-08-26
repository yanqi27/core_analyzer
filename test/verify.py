
import sys
import gdb

gdb.execute('file ./mallocTest')

gdb.execute ('run')

print ""
print "Check heap regions......................."

#def check():
n = gdb.parse_and_eval("num_regions")
blks = gdb.parse_and_eval("regions")
i = 0
while i < n:
	blk = blks + i
	addr = int(blk['p'].cast(gdb.lookup_type('long')))
	my_blk = gdb.heap_block(addr)
	match = True
	if blk['inuse']:
		if blk['p'] != my_blk.address or blk['size'] != my_blk.size or  not my_blk.inuse:
			match = False
	else:
		if my_blk.inuse:
			match = False

	if not match:
		print "[%d] addr=0x%x size=%u inuse=%d" % (i, blk['p'], blk['size'], blk['inuse'])
		print "[%d] addr=0x%x size=%u inuse=%d" % (i, my_blk.address, my_blk.size, my_blk.inuse)
		raise Exception('core analyzer returns wrong heap block info')

	i = i + 1
print "%d heap memory blocks are verified" % (n)
print "Passed ......................."
print ""

gdb.execute ('set confirm off')
gdb.execute ('quit')

