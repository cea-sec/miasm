
typedef struct {
	uint32_t exception_flags;

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

}vm_cpu_t;

#define RETURN_PC return BlockDst;

uint16_t bcdadd_16(uint16_t a, uint16_t b);

uint16_t bcdadd_cf_16(uint16_t a, uint16_t b);

uint16_t hex2bcd_16(uint16_t a);

uint8_t hex2bcd_8(uint8_t a);

uint8_t bcd2hex_8(uint8_t a);

uint16_t bcd2hex_16(uint16_t a);

void dump_gpregs(vm_cpu_t* vmcpu);
