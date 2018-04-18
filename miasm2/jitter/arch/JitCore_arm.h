
typedef struct {
	uint32_t exception_flags;

	/* gpregs */
	uint32_t R0;
	uint32_t R1;
	uint32_t R2;
	uint32_t R3;
	uint32_t R4;
	uint32_t R5;
	uint32_t R6;
	uint32_t R7;
	uint32_t R8;
	uint32_t R9;
	uint32_t R10;
	uint32_t R11;
	uint32_t R12;
	uint32_t SP;
	uint32_t LR;
	uint32_t PC;

	/* eflag */
	uint32_t zf;
	uint32_t nf;
	uint32_t of;
	uint32_t cf;

	/* ge */
	uint32_t ge0;
	uint32_t ge1;
	uint32_t ge2;
	uint32_t ge3;

	uint32_t bp_num;
}vm_cpu_t;


void dump_gpregs(vm_cpu_t* vmcpu);


uint32_t udiv32(vm_cpu_t* vmcpu, uint32_t a, uint32_t b);
uint32_t umod32(vm_cpu_t* vmcpu, uint32_t a, uint32_t b);
int32_t idiv32(vm_cpu_t* vmcpu, int32_t a, int32_t b);
int32_t imod32(vm_cpu_t* vmcpu, int32_t a, int32_t b);


#define RETURN_PC return BlockDst;

uint32_t clz(uint32_t arg);
