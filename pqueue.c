#include "types.h"
#include "defs.h"
#include "memlayout.h"
#include "mmu.h"
#include "param.h"
#include "proc.h"
#include "spinlock.h"
#include "traps.h"
#include "x86.h"

struct pqueue *pq_get(void)
{
    for (int i=0; i<NPROC; i++)
    {
        if(extra[i].free==0)
        {
            extra[i].free=1;
            return &extra[i];
        }
    }
    return 0;
}

void pq_release(struct pqueue *in)
{
    in->free=0;
}