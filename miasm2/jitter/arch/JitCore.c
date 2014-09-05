#include <Python.h>
#include "JitCore.h"

block_id Resolve_dst(uint64_t addr, uint64_t is_local)
{
	block_id b;
	b.address = addr;
	b.is_local = is_local;
	return b;
}
