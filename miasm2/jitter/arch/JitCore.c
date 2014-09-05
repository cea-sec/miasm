#include <Python.h>
#include "JitCore.h"

void Resolve_dst(block_id* b, uint64_t addr, uint64_t is_local)
{
	b->address = addr;
	b->is_local = is_local;
}
