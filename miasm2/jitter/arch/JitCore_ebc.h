typedef struct {
	uint32_t exception_flags;
	uint32_t exception_flags_new;

	uint64_t IP;
	uint64_t R0;
	uint64_t R1;
	uint64_t R2;
	uint64_t R3;
	uint64_t R4;
	uint64_t R5;
	uint64_t R6;
	uint64_t R7;
        uint64_t IP_new;
        uint64_t R0_new;
        uint64_t R1_new;
        uint64_t R2_new;
        uint64_t R3_new;
        uint64_t R4_new;
        uint64_t R5_new;
        uint64_t R6_new;
        uint64_t R7_new;
	uint64_t cf;
	uint64_t sf;
	uint64_t cf_new;
	uint64_t sf_new;

        uint8_t  pfmem08_0;
        uint16_t pfmem16_0;
        uint32_t pfmem32_0;
        uint64_t pfmem64_0;

}vm_cpu_t;

#define RETURN_PC return BlockDst;

uint16_t bcdadd_16(uint16_t a, uint16_t b);
uint16_t bcdadd_cf_16(uint16_t a, uint16_t b);
uint16_t hex2bcd_16(uint16_t a);
uint8_t  hex2bcd_8(uint8_t a);
uint8_t  bcd2hex_8(uint8_t a);
uint16_t bcd2hex_16(uint16_t a);

