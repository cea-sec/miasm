
typedef struct {
	uint32_t exception_flags;
	uint32_t exception_flags_new;

	/* gpregs */

	uint32_t ZERO;
	uint32_t AT;
	uint32_t V0;
	uint32_t V1;
	uint32_t A0;
	uint32_t A1;
	uint32_t A2;
	uint32_t A3;
	uint32_t T0;
	uint32_t T1;
	uint32_t T2;
	uint32_t T3;
	uint32_t T4;
	uint32_t T5;
	uint32_t T6;
	uint32_t T7;
	uint32_t S0;
	uint32_t S1;
	uint32_t S2;
	uint32_t S3;
	uint32_t S4;
	uint32_t S5;
	uint32_t S6;
	uint32_t S7;
	uint32_t T8;
	uint32_t T9;
	uint32_t K0;
	uint32_t K1;
	uint32_t GP;
	uint32_t SP;
	uint32_t FP;
	uint32_t RA;
	uint32_t PC;

	uint32_t ZERO_new;
	uint32_t AT_new;
	uint32_t V0_new;
	uint32_t V1_new;
	uint32_t A0_new;
	uint32_t A1_new;
	uint32_t A2_new;
	uint32_t A3_new;
	uint32_t T0_new;
	uint32_t T1_new;
	uint32_t T2_new;
	uint32_t T3_new;
	uint32_t T4_new;
	uint32_t T5_new;
	uint32_t T6_new;
	uint32_t T7_new;
	uint32_t S0_new;
	uint32_t S1_new;
	uint32_t S2_new;
	uint32_t S3_new;
	uint32_t S4_new;
	uint32_t S5_new;
	uint32_t S6_new;
	uint32_t S7_new;
	uint32_t T8_new;
	uint32_t T9_new;
	uint32_t K0_new;
	uint32_t K1_new;
	uint32_t GP_new;
	uint32_t SP_new;
	uint32_t FP_new;
	uint32_t RA_new;
	uint32_t PC_new;



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



#define RETURN_PC return PyLong_FromUnsignedLongLong(vmcpu->PC);
