
import shutil
import sys
import os
def copy_file(src, dest):
    print('copying {} to {}'.format(src, dest))
    shutil.copy2(src, dest) # copy2 will preserve some useful information hoping to avoid recompile if the file deoes not change
                            # https://stackoverflow.com/a/30359308/2651597
def check_dir(d):
    if not os.path.isdir(d):
        print(src + ' does not exist, please double check.')
        return False
    return True

file_not_to_copy = [
    "ca_elf.h",
    "core_elf.cpp",
    "core_pe_x86.cpp",
    "cross_platform.h",
    "heap_darwin.cpp",
    "heap_darwin.h",
    "heap_mscrt.cpp",
    "heap_mscrt.h",
    "mmap_file.h",
]
g_c_files = []
g_c_h_files = []
g_python_c_files = []
g_python_h_files = []

def copy_core_analyzer_files(src, dest):
    for f in os.listdir(src):
        old_file = src + '/' + f
        if os.path.isdir(old_file):
            copy_core_analyzer_files(old_file, dest +'/' + f)

        elif f not in file_not_to_copy:
            new_file = dest + '/' + f
            if f.endswith('.cpp'):
                c_file = f[:-4] + '.c'
                new_file = dest + '/' + c_file
                if f.startswith('python/'):
                    g_python_c_files.append(c_file)
                else:
                    g_c_files.append(c_file)
            elif f.endswith('.h'):
                if f.startswith('python/'):
                    g_python_h_files.append(f)
                else:
                    g_c_h_files.append(f)
            else:
                print('{} will be copied'.format(f))

            copy_file(old_file, new_file)


def modify_gdb_makefile(dest):
    makefile = dest + '/' + 'Makefile.in' # it is unlikely that gdb will change the make file
    makefile_tmp = makefile + '.tmp'
    with open(makefile_tmp, 'w') as w:
        with open(makefile, 'r') as f:
            for line in f.readlines():
                w.write(line)
                # find the anchor line to inject our c files
                if line == "	value.c \\\n":
                    for c_file in g_c_files:
                        w.write('\t' + c_file + '\\\n')
                        
                # find the anchor line to inject our python c files
                if line == "	python/py-value.c \\\n":
                    for c_python_file in g_python_c_files:
                        w.write('\t' + c_python_file + '\\\n')
                # find the anchor line to inject our python h files
                if line == "	python/python.h \\\n":
                    for python_h_file in g_python_h_files:
                        w.write('\t' + python_h_file + '\\\n')

    
    os.remove(makefile)
    shutil.copy2(makefile_tmp, makefile)
if __name__ == '__main__':
    # python <script.py> arg1 arg2
    if len(sys.argv) != 3:
        print('please provide source and destination of the files to copy.')
        sys.exit(1)
        
    src = sys.argv[1]
    dest = sys.argv[2]
    if not check_dir(src):
        sys.exit(1)
    if not check_dir(dest):
        sys.exit(1)
    
    copy_core_analyzer_files(src, dest)
    modify_gdb_makefile(dest)



