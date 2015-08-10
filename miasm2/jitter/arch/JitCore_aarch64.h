
typedef struct {
	uint32_t exception_flags;
	uint32_t exception_flags_new;

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


	uint64_t X0_new;
	uint64_t X1_new;
	uint64_t X2_new;
	uint64_t X3_new;
	uint64_t X4_new;
	uint64_t X5_new;
	uint64_t X6_new;
	uint64_t X7_new;
	uint64_t X8_new;
	uint64_t X9_new;
	uint64_t X10_new;
	uint64_t X11_new;
	uint64_t X12_new;
	uint64_t X13_new;
	uint64_t X14_new;
	uint64_t X15_new;
	uint64_t X16_new;
	uint64_t X17_new;
	uint64_t X18_new;
	uint64_t X19_new;
	uint64_t X20_new;
	uint64_t X21_new;
	uint64_t X22_new;
	uint64_t X23_new;
	uint64_t X24_new;
	uint64_t X25_new;
	uint64_t X26_new;
	uint64_t X27_new;
	uint64_t X28_new;
	uint64_t X29_new;
	uint64_t LR_new;
	uint64_t SP_new;

	uint64_t PC_new;

	/* eflag */
	uint32_t zf;
	uint32_t nf;
	uint32_t of;
	uint32_t cf;

	uint32_t zf_new;
	uint32_t nf_new;
	uint32_t of_new;
	uint32_t cf_new;


	uint8_t pfmem08_0;
	uint8_t pfmem08_1;
	uint8_t pfmem08_2;
	uint8_t pfmem08_3;
	uint8_t pfmem08_4;
	uint8_t pfmem08_5;
	uint8_t pfmem08_6;
	uint8_t pfmem08_7;
	uint8_t pfmem08_8;
	uint8_t pfmem08_9;
	uint8_t pfmem08_10;
	uint8_t pfmem08_11;
	uint8_t pfmem08_12;
	uint8_t pfmem08_13;
	uint8_t pfmem08_14;
	uint8_t pfmem08_15;
	uint8_t pfmem08_16;
	uint8_t pfmem08_17;
	uint8_t pfmem08_18;
	uint8_t pfmem08_19;


	uint16_t pfmem16_0;
	uint16_t pfmem16_1;
	uint16_t pfmem16_2;
	uint16_t pfmem16_3;
	uint16_t pfmem16_4;
	uint16_t pfmem16_5;
	uint16_t pfmem16_6;
	uint16_t pfmem16_7;
	uint16_t pfmem16_8;
	uint16_t pfmem16_9;
	uint16_t pfmem16_10;
	uint16_t pfmem16_11;
	uint16_t pfmem16_12;
	uint16_t pfmem16_13;
	uint16_t pfmem16_14;
	uint16_t pfmem16_15;
	uint16_t pfmem16_16;
	uint16_t pfmem16_17;
	uint16_t pfmem16_18;
	uint16_t pfmem16_19;


	uint32_t pfmem32_0;
	uint32_t pfmem32_1;
	uint32_t pfmem32_2;
	uint32_t pfmem32_3;
	uint32_t pfmem32_4;
	uint32_t pfmem32_5;
	uint32_t pfmem32_6;
	uint32_t pfmem32_7;
	uint32_t pfmem32_8;
	uint32_t pfmem32_9;
	uint32_t pfmem32_10;
	uint32_t pfmem32_11;
	uint32_t pfmem32_12;
	uint32_t pfmem32_13;
	uint32_t pfmem32_14;
	uint32_t pfmem32_15;
	uint32_t pfmem32_16;
	uint32_t pfmem32_17;
	uint32_t pfmem32_18;
	uint32_t pfmem32_19;


	uint64_t pfmem64_0;
	uint64_t pfmem64_1;
	uint64_t pfmem64_2;
	uint64_t pfmem64_3;
	uint64_t pfmem64_4;
	uint64_t pfmem64_5;
	uint64_t pfmem64_6;
	uint64_t pfmem64_7;
	uint64_t pfmem64_8;
	uint64_t pfmem64_9;
	uint64_t pfmem64_10;
	uint64_t pfmem64_11;
	uint64_t pfmem64_12;
	uint64_t pfmem64_13;
	uint64_t pfmem64_14;
	uint64_t pfmem64_15;
	uint64_t pfmem64_16;
	uint64_t pfmem64_17;
	uint64_t pfmem64_18;
	uint64_t pfmem64_19;

}vm_cpu_t;


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
