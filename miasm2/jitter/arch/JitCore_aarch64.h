
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

uint64_t udiv64(vm_cpu_t* vmcpu, uint64_t a, uint64_t b);
uint64_t umod64(vm_cpu_t* vmcpu, uint64_t a, uint64_t b);
int64_t idiv64(vm_cpu_t* vmcpu, int64_t a, int64_t b);
int64_t imod64(vm_cpu_t* vmcpu, int64_t a, int64_t b);

uint32_t udiv32(vm_cpu_t* vmcpu, uint32_t a, uint32_t b);
uint32_t umod32(vm_cpu_t* vmcpu, uint32_t a, uint32_t b);
int32_t idiv32(vm_cpu_t* vmcpu, int32_t a, int32_t b);
int32_t imod32(vm_cpu_t* vmcpu, int32_t a, int32_t b);

uint16_t udiv16(vm_cpu_t* vmcpu, uint16_t a, uint16_t b);
uint16_t umod16(vm_cpu_t* vmcpu, uint16_t a, uint16_t b);
int16_t idiv16(vm_cpu_t* vmcpu, int16_t a, int16_t b);
int16_t imod16(vm_cpu_t* vmcpu, int16_t a, int16_t b);

#define RETURN_PC return BlockDst;
