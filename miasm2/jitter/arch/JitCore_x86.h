
typedef struct {
	uint32_t exception_flags;
	uint32_t exception_flags_new;


	/* gpregs */
	uint64_t RAX;
	uint64_t RBX;
	uint64_t RCX;
	uint64_t RDX;
	uint64_t RSI;
	uint64_t RDI;
	uint64_t RSP;
	uint64_t RBP;
	uint64_t R8;
	uint64_t R9;
	uint64_t R10;
	uint64_t R11;
	uint64_t R12;
	uint64_t R13;
	uint64_t R14;
	uint64_t R15;

	uint64_t RIP;

	uint64_t RAX_new;
	uint64_t RBX_new;
	uint64_t RCX_new;
	uint64_t RDX_new;
	uint64_t RSI_new;
	uint64_t RDI_new;
	uint64_t RSP_new;
	uint64_t RBP_new;
	uint64_t R8_new;
	uint64_t R9_new;
	uint64_t R10_new;
	uint64_t R11_new;
	uint64_t R12_new;
	uint64_t R13_new;
	uint64_t R14_new;
	uint64_t R15_new;

	uint64_t RIP_new;

	/* eflag */
	uint64_t zf;
	uint64_t nf;
	uint64_t pf;
	uint64_t of;
	uint64_t cf;
	uint64_t af;
	uint64_t df;

	uint64_t zf_new;
	uint64_t nf_new;
	uint64_t pf_new;
	uint64_t of_new;
	uint64_t cf_new;
	uint64_t af_new;
	uint64_t df_new;

	uint64_t tf;
	uint64_t i_f;
	uint64_t iopl_f;
	uint64_t nt;
	uint64_t rf;
	uint64_t vm;
	uint64_t ac;
	uint64_t vif;
	uint64_t vip;
	uint64_t i_d;

	uint64_t tf_new;
	uint64_t i_f_new;
	uint64_t iopl_f_new;
	uint64_t nt_new;
	uint64_t rf_new;
	uint64_t vm_new;
	uint64_t ac_new;
	uint64_t vif_new;
	uint64_t vip_new;
	uint64_t i_d_new;

	uint64_t my_tick;

	uint64_t cond;

	double float_st0;
	double float_st1;
	double float_st2;
	double float_st3;
	double float_st4;
	double float_st5;
	double float_st6;
	double float_st7;

	double float_st0_new;
	double float_st1_new;
	double float_st2_new;
	double float_st3_new;
	double float_st4_new;
	double float_st5_new;
	double float_st6_new;
	double float_st7_new;

	unsigned int float_c0;
	unsigned int float_c1;
	unsigned int float_c2;
	unsigned int float_c3;

	unsigned int float_c0_new;
	unsigned int float_c1_new;
	unsigned int float_c2_new;
	unsigned int float_c3_new;

	unsigned int float_stack_ptr;
	unsigned int float_stack_ptr_new;

	unsigned int reg_float_control;
	unsigned int reg_float_control_new;

	unsigned int reg_float_eip;
	unsigned int reg_float_eip_new;
	unsigned int reg_float_cs;
	unsigned int reg_float_cs_new;
	unsigned int reg_float_address;
	unsigned int reg_float_address_new;
	unsigned int reg_float_ds;
	unsigned int reg_float_ds_new;


	unsigned int tsc1;
	unsigned int tsc2;

	unsigned int tsc1_new;
	unsigned int tsc2_new;


	uint64_t ES;
	uint64_t CS;
	uint64_t SS;
	uint64_t DS;
	uint64_t FS;
	uint64_t GS;

	uint64_t ES_new;
	uint64_t CS_new;
	uint64_t SS_new;
	uint64_t DS_new;
	uint64_t FS_new;
	uint64_t GS_new;

	unsigned int cr0;
	unsigned int cr0_new;

	unsigned int cr3;
	unsigned int cr3_new;



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


	uint64_t MM0;
	uint64_t MM1;
	uint64_t MM2;
	uint64_t MM3;
	uint64_t MM4;
	uint64_t MM5;
	uint64_t MM6;
	uint64_t MM7;

	uint64_t MM0_new;
	uint64_t MM1_new;
	uint64_t MM2_new;
	uint64_t MM3_new;
	uint64_t MM4_new;
	uint64_t MM5_new;
	uint64_t MM6_new;
	uint64_t MM7_new;

	uint32_t segm_base[0x10000];

}vm_cpu_t;



void dump_gpregs(vm_cpu_t* vmcpu);
uint64_t segm2addr(vm_cpu_t* vmcpu, uint64_t segm, uint64_t addr);


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

#define RETURN_PC return PyLong_FromUnsignedLongLong(vmcpu->RIP);
