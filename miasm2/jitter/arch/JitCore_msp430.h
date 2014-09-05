
typedef struct {
	uint32_t exception_flags;
	uint32_t exception_flags_new;

	/* gpregs */
	uint32_t PC;
	uint32_t SP;
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
	uint32_t R13;
	uint32_t R14;
	uint32_t R15;

	uint32_t PC_new;
	uint32_t SP_new;
	uint32_t SR_new;
	uint32_t R3_new;
	uint32_t R4_new;
	uint32_t R5_new;
	uint32_t R6_new;
	uint32_t R7_new;
	uint32_t R8_new;
	uint32_t R9_new;
	uint32_t R10_new;
	uint32_t R11_new;
	uint32_t R12_new;
	uint32_t R13_new;
	uint32_t R14_new;
	uint32_t R15_new;

	/* eflag */
	uint32_t zf;
	uint32_t nf;
	uint32_t of;
	uint32_t cf;

	uint32_t cpuoff;
	uint32_t gie;
	uint32_t osc;
	uint32_t scg0;
	uint32_t scg1;
	uint32_t res;


	uint32_t zf_new;
	uint32_t nf_new;
	uint32_t of_new;
	uint32_t cf_new;

	uint32_t cpuoff_new;
	uint32_t gie_new;
	uint32_t osc_new;
	uint32_t scg0_new;
	uint32_t scg1_new;
	uint32_t res_new;


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


	uint32_t segm_base[0x10000];

}vm_cpu_t;

//#define RETURN_PC return PyLong_FromUnsignedLongLong(vmcpu->PC);
#define RETURN_PC return BlockDst;

uint16_t bcdadd_16(uint16_t a, uint16_t b);

uint16_t bcdadd_cf_16(uint16_t a, uint16_t b);

uint16_t hex2bcd_16(uint16_t a);

uint8_t hex2bcd_8(uint8_t a);

uint8_t bcd2hex_8(uint8_t a);

uint16_t bcd2hex_16(uint16_t a);
