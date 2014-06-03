all: vm_mngr.so Jit_x86.so Jittcc.so
	

vm_mngr.so: vm_mngr.c vm_mngr.h vm_mngr_py.c
	gcc -I /usr/include/python2.7  -shared -fPIC vm_mngr.c vm_mngr_py.c -o vm_mngr.so

Jit_x86.so: arch/Jit_x86.c
	gcc -I /usr/include/python2.7  -shared -fPIC arch/Jit_x86.c -o arch/Jit_x86.so

Jit_arm.so: arch/Jit_arm.c
	gcc -I /usr/include/python2.7  -shared -fPIC arch/Jit_arm.c -o arch/Jit_arm.so

Jittcc.so: Jittcc.c
	gcc -I /usr/include/python2.7  -shared -fPIC Jittcc.c -o Jittcc.so -ltcc

clean:
	rm vm_mngr.so Jittcc.so arch/Jit_x86.so