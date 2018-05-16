
typedef struct {
	uint32_t exception_flags;
	uint32_t interrupt_num;

	/* gpregs */

	uint64_t X0;
	uint64_t X1;
	uint64_t X2;
	uint64_t X3;
	uint64_t X4;
	uint64_t X5;
	uint64_t X6;
	uint64_t X7;
	uint64_t X8;
	uint64_t X9;
	uint64_t X10;
	uint64_t X11;
	uint64_t X12;
	uint64_t X13;
	uint64_t X14;
	uint64_t X15;
	uint64_t X16;
	uint64_t X17;
	uint64_t X18;
	uint64_t X19;
	uint64_t X20;
	uint64_t X21;
	uint64_t X22;
	uint64_t X23;
	uint64_t X24;
	uint64_t X25;
	uint64_t X26;
	uint64_t X27;
	uint64_t X28;
	uint64_t X29;
	uint64_t LR;
	uint64_t SP;

	uint64_t PC;

	/* eflag */
	uint32_t zf;
	uint32_t nf;
	uint32_t of;
	uint32_t cf;
}vm_cpu_t;

void dump_gpregs(vm_cpu_t* vmcpu);

#define RETURN_PC return BlockDst;
