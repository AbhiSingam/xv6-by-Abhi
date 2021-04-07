#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "x86.h"
#include "proc.h"
#include "spinlock.h"

struct {
  struct spinlock lock;
  struct proc proc[NPROC];
} ptable;

static struct proc *initproc;

int nextpid = 1;
extern void forkret(void);
extern void trapret(void);

static void wakeup1(void *chan);

void
pinit(void)
{
  initlock(&ptable.lock, "ptable");
  
#ifdef MLFQ
  // acquire(&ptable.lock);
  for (int i = 0; i < 5; i++)
  {
    q_arr[i] = 0;
  }
  for (int i = 0; i < NPROC; i++)
  {
    extra[i].free = 0;
  }
  // release(&ptable.lock);
#endif
}

// Must be called with interrupts disabled
int
cpuid() {
  return mycpu()-cpus;
}

// Must be called with interrupts disabled to avoid the caller being
// rescheduled between reading lapicid and running through the loop.
struct cpu*
mycpu(void)
{
  int apicid, i;
  
  if(readeflags()&FL_IF)
    panic("mycpu called with interrupts enabled\n");
  
  apicid = lapicid();
  // APIC IDs are not guaranteed to be contiguous. Maybe we should have
  // a reverse map, or reserve a register to store &cpus[i].
  for (i = 0; i < ncpu; ++i) {
    if (cpus[i].apicid == apicid)
      return &cpus[i];
  }
  panic("unknown apicid\n");
}

// Disable interrupts so that we are not rescheduled
// while reading proc from the cpu structure
struct proc*
myproc(void) {
  struct cpu *c;
  struct proc *p;
  pushcli();
  c = mycpu();
  p = c->proc;
  popcli();
  return p;
}

//PAGEBREAK: 32
// Look in the process table for an UNUSED proc.
// If found, change state to EMBRYO and initialize
// state required to run in the kernel.
// Otherwise return 0.
static struct proc*
allocproc(void)
{
  struct proc *p;
  char *sp;

  acquire(&ptable.lock);

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if(p->state == UNUSED)
      goto found;

  release(&ptable.lock);
  return 0;

found:
  p->state = EMBRYO;
  //process start
  p->pid = nextpid++;
  p->ctime = ticks;                //TIME OF BIRTH
  p->rtime = 0;
  p->etime = 0;
  p->sleep_time = 0;
  p->mlfq_wait = 0;
  p->cur_q = 0;
  
  #ifdef MLFQ
  struct pqueue *pq = pq_get();
  p->qnode=pq;
  pq->proc = p;
  pq->next = q_arr[p->cur_q];
  if(q_arr[p->cur_q]!=0)
  {
    q_arr[p->cur_q]->back=pq;
  }
  pq->back = 0;
  q_arr[p->cur_q]=pq;
  #endif

  cprintf("\nGRAPH %d %d %d\n", p->pid, p->cur_q, ticks);

  p->q[0] = 0;
  p->q[1] = 0;
  p->q[2] = 0;
  p->q[3] = 0;
  p->q[4] = 0;
  p->burst[0] = 0;
  p->burst[1] = 0;
  p->burst[2] = 0;
  p->burst[3] = 0;
  p->burst[4] = 0;
  p->n_run = 0;
  p->priority = 60;                //Standard priority = 60

  release(&ptable.lock);

  // Allocate kernel stack.
  if((p->kstack = kalloc()) == 0){
    p->state = UNUSED;
    return 0;
  }
  sp = p->kstack + KSTACKSIZE;

  // Leave room for trap frame.
  sp -= sizeof *p->tf;
  p->tf = (struct trapframe*)sp;

  // Set up new context to start executing at forkret,
  // which returns to trapret.
  sp -= 4;
  *(uint*)sp = (uint)trapret;

  sp -= sizeof *p->context;
  p->context = (struct context*)sp;
  memset(p->context, 0, sizeof *p->context);
  p->context->eip = (uint)forkret;

  return p;
}

//PAGEBREAK: 32
// Set up first user process.
void
userinit(void)
{
  struct proc *p;
  extern char _binary_initcode_start[], _binary_initcode_size[];

  p = allocproc();
  
  initproc = p;
  if((p->pgdir = setupkvm()) == 0)
    panic("userinit: out of memory?");
  inituvm(p->pgdir, _binary_initcode_start, (int)_binary_initcode_size);
  p->sz = PGSIZE;
  memset(p->tf, 0, sizeof(*p->tf));
  p->tf->cs = (SEG_UCODE << 3) | DPL_USER;
  p->tf->ds = (SEG_UDATA << 3) | DPL_USER;
  p->tf->es = p->tf->ds;
  p->tf->ss = p->tf->ds;
  p->tf->eflags = FL_IF;
  p->tf->esp = PGSIZE;
  p->tf->eip = 0;  // beginning of initcode.S

  safestrcpy(p->name, "initcode", sizeof(p->name));
  p->cwd = namei("/");

  // this assignment to p->state lets other cores
  // run this process. the acquire forces the above
  // writes to be visible, and the lock is also needed
  // because the assignment might not be atomic.
  acquire(&ptable.lock);

  p->state = RUNNABLE;

  release(&ptable.lock);
}

// Grow current process's memory by n bytes.
// Return 0 on success, -1 on failure.
int
growproc(int n)
{
  uint sz;
  struct proc *curproc = myproc();

  sz = curproc->sz;
  if(n > 0){
    if((sz = allocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  } else if(n < 0){
    if((sz = deallocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  }
  curproc->sz = sz;
  switchuvm(curproc);
  return 0;
}

// Create a new process copying p as the parent.
// Sets up stack to return as if from system call.
// Caller must set state of returned proc to RUNNABLE.
int
fork(void)
{
  int i, pid;
  struct proc *np;
  struct proc *curproc = myproc();

  // Allocate process.
  if((np = allocproc()) == 0){
    return -1;
  }

  // Copy process state from proc.
  if((np->pgdir = copyuvm(curproc->pgdir, curproc->sz)) == 0){
    kfree(np->kstack);
    np->kstack = 0;
    np->state = UNUSED;
    return -1;
  }
  np->sz = curproc->sz;
  np->parent = curproc;
  *np->tf = *curproc->tf;

  // Clear %eax so that fork returns 0 in the child.
  np->tf->eax = 0;

  for(i = 0; i < NOFILE; i++)
    if(curproc->ofile[i])
      np->ofile[i] = filedup(curproc->ofile[i]);
  np->cwd = idup(curproc->cwd);

  safestrcpy(np->name, curproc->name, sizeof(curproc->name));

  pid = np->pid;

  acquire(&ptable.lock);

  np->state = RUNNABLE;

  release(&ptable.lock);

  return pid;
}

// Exit the current process.  Does not return.
// An exited process remains in the zombie state
// until its parent calls wait() to find out it exited.
void
exit(void)
{
  //process death
  struct proc *curproc = myproc();
  struct proc *p;
  int fd;

  if(curproc == initproc)
    panic("init exiting");

  // Close all open files.
  for(fd = 0; fd < NOFILE; fd++){
    if(curproc->ofile[fd]){
      fileclose(curproc->ofile[fd]);
      curproc->ofile[fd] = 0;
    }
  }

  begin_op();
  iput(curproc->cwd);
  end_op();
  curproc->cwd = 0;

  acquire(&ptable.lock);

  // Parent might be sleeping in wait().
  wakeup1(curproc->parent);

  // Pass abandoned children to init.
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->parent == curproc){
      p->parent = initproc;
      if(p->state == ZOMBIE)
        wakeup1(initproc);
    }
  }

  // Jump into the scheduler, never to return.
  curproc->state = ZOMBIE;
  curproc->etime = ticks;                //TIME TO DIE
  
  #ifdef MLFQ
    if(curproc->qnode->back!=0)
    {
      curproc->qnode->back->next=curproc->qnode->next;
    }
    if(curproc->qnode->next!=0)
    {
      curproc->qnode->next->back=curproc->qnode->back;
    }
    if(curproc->qnode->next==0 && curproc->qnode->back==0)
    {
      q_arr[curproc->cur_q]=0;
    }
    curproc->qnode->back=0;
    curproc->qnode->next=0;
    pq_release(curproc->qnode);
  #endif
  
  sched();
  panic("zombie exit");
}

// Wait for a child process to exit and return its pid.
// Return -1 if this process has no children.
int
wait(void)
{
  struct proc *p;
  int havekids, pid;
  struct proc *curproc = myproc();
  
  acquire(&ptable.lock);
  for(;;){
    // Scan through table looking for exited children.
    havekids = 0;
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
      if(p->parent != curproc)
        continue;
      havekids = 1;
      if(p->state == ZOMBIE){
        // Found one.
        pid = p->pid;
        kfree(p->kstack);
        p->kstack = 0;
        freevm(p->pgdir);
        p->pid = 0;
        p->parent = 0;
        p->name[0] = 0;
        p->killed = 0;
        p->state = UNUSED;
        release(&ptable.lock);
        return pid;
      }
    }

    // No point waiting if we don't have any children.
    if(!havekids || curproc->killed){
      release(&ptable.lock);
      return -1;
    }

    // Wait for children to exit.  (See wakeup1 call in proc_exit.)
    sleep(curproc, &ptable.lock);  //DOC: wait-sleep
  }
}
//Abhi's waitx
int
waitx(int *wtime, int *rtime)
{
  struct proc *p;
  int havekids, pid;
  struct proc *curproc = myproc();

  acquire(&ptable.lock);
  for (;;)
  {
    // Scan through table looking for exited children.
    havekids = 0;
    for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    {
      if (p->parent != curproc)
        continue;
      havekids = 1;
      if (p->state == ZOMBIE)
      {
        // Found one.
        *rtime = p->rtime;
        *wtime = p->etime - p->ctime - p->rtime - p->sleep_time;      //Waits for the time it's not running = tot_time - run_time
        pid = p->pid;
        kfree(p->kstack);
        p->kstack = 0;
        freevm(p->pgdir);
        p->pid = 0;
        p->parent = 0;
        p->name[0] = 0;
        p->killed = 0;
        p->state = UNUSED;
        release(&ptable.lock);
        return pid;
      }
    }

    // No point waiting if we don't have any children.
    if (!havekids || curproc->killed)
    {
      release(&ptable.lock);
      return -1;
    }

    // Wait for children to exit.  (See wakeup1 call in proc_exit.)
    sleep(curproc, &ptable.lock); //DOC: wait-sleep
  }
}

int
set_priority(int priority, int pid)
{
  struct proc *p;
  int prev_pr=-1;

  if(priority>100 || priority<0)
  {
    // printf(2,"ERROR: set_priority: Invalid process priority\n"); 
    return -1;
  }

  acquire(&ptable.lock);

  for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
  {
    if(p->pid==pid)
    {
      prev_pr=p->priority;
      p->priority=priority;
      break;
    }
  }
  release(&ptable.lock);

  if(prev_pr!=priority)
  {
    yield();
  }

  return prev_pr;
}

int
psys(void)
{
  struct proc *p;

  acquire(&ptable.lock);

  cprintf(" PID\tPriority\tState\t\tr_time\tw_time\tn_run\tcur_q\tq0\tq1\tq2\tq3\tq4\tb0\tb1\tb2\tb3\tb4\n");
  for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
  {
    int pid = p->pid, priority = p->priority, r_time = p->rtime;

    if (p->state == RUNNING)
    {
      cprintf(" %d\t%d\t\tRunning\t\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", pid, priority, r_time, p->mlfq_wait, p->n_run, p->cur_q, p->q[0], p->q[1], p->q[2], p->q[3], p->q[4], p->burst[0], p->burst[1], p->burst[2], p->burst[3], p->burst[4]);
    }
    else if (p->state == RUNNABLE)
    {
      cprintf(" %d\t%d\t\tRunnable\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", pid, priority, r_time, p->mlfq_wait, p->n_run, p->cur_q, p->q[0], p->q[1], p->q[2], p->q[3], p->q[4], p->burst[0], p->burst[1], p->burst[2], p->burst[3], p->burst[4]);
    }
    else if (p->state == SLEEPING)
    {
      cprintf(" %d\t%d\t\tSleeping\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", pid, priority, r_time, p->mlfq_wait, p->n_run, p->cur_q, p->q[0], p->q[1], p->q[2], p->q[3], p->q[4], p->burst[0], p->burst[1], p->burst[2], p->burst[3], p->burst[4]);
    }
    else if (p->state == ZOMBIE)
    {
      cprintf(" %d\t%d\t\tZombie\t\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", pid, priority, r_time, p->mlfq_wait, p->n_run, p->cur_q, p->q[0], p->q[1], p->q[2], p->q[3], p->q[4], p->burst[0], p->burst[1], p->burst[2], p->burst[3], p->burst[4]);
    }
    else if (p->state == EMBRYO)
    {
      cprintf(" %d\t%d\t\tEmbryo\t\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", pid, priority, r_time, p->mlfq_wait, p->n_run, p->cur_q, p->q[0], p->q[1], p->q[2], p->q[3], p->q[4], p->burst[0], p->burst[1], p->burst[2], p->burst[3], p->burst[4]);
    }
  }
  // cprintf("q_arr: %p %p %p %p %p\n", q_arr[0], q_arr[1], q_arr[2], q_arr[3], q_arr[4]);
  // cprintf("\n");
  release(&ptable.lock);
  return 0;
}

//PAGEBREAK: 42
// Per-CPU process scheduler.
// Each CPU calls scheduler() after setting itself up.
// Scheduler never returns.  It loops, doing:
//  - choose a process to run
//  - swtch to start running that process
//  - eventually that process transfers control
//      via swtch back to the scheduler.

void
scheduler(void)
{
  #ifdef RR
  // cprintf("\n\nUSING RR\n\n");
  struct proc *p;
  struct cpu *c = mycpu();
  c->proc = 0;
  
  for(;;){
    // Enable interrupts on this processor.
    sti();

    // Loop over process table looking for process to run.
    acquire(&ptable.lock);
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
      if(p->state != RUNNABLE)
        continue;

      // Switch to chosen process.  It is the process's job
      // to release ptable.lock and then reacquire it
      // before jumping back to us.
      p->n_run++;
      c->proc = p;
      switchuvm(p);
      p->state = RUNNING;

      swtch(&(c->scheduler), p->context);
      switchkvm();

      // Process is done running for now.
      // It should have changed its p->state before coming back.
      c->proc = 0;
    }
    release(&ptable.lock);

  }
  #else

  #ifdef FCFS
  // cprintf("\n\nUSING FCFS\n\n");
  struct proc *p, *pfinal;
  struct cpu *c = mycpu();
  c->proc = 0;

  for (;;)
  {
    // Enable interrupts on this processor.
    sti();

    // Loop over process table looking for process to run.
    acquire(&ptable.lock);
    int flag = 0;
    pfinal = 0;
    for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    {
      if (p->state == RUNNABLE)
      {
        flag=1;
        pfinal=p;
        break;
      }
    }
    if(flag==1)
    {
      p=pfinal;
      // Switch to chosen process.  It is the process's job
      // to release ptable.lock and then reacquire it
      // before jumping back to us.
      p->n_run++;
      c->proc = p;
      switchuvm(p);
      p->state = RUNNING;

      swtch(&(c->scheduler), p->context);
      switchkvm();

      // Process is done running for now.
      // It should have changed its p->state before coming back.
      c->proc = 0;
    }
    release(&ptable.lock);
  }
  #else

  #ifdef PBS

  struct proc *p, *plist[NPROC];
  struct cpu *c = mycpu();
  c->proc = 0;

  for (;;)
  {
    // Enable interrupts on this processor.
    sti();

    // Loop over process table looking for process to run.
    int rr_count=0, min_prior=100;
    acquire(&ptable.lock);
    // int flag = 0;
    // pfinal = 0;
    for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    {
      if (p->state == RUNNABLE)
      {
        if(p->priority<min_prior)
        {
          min_prior=p->priority;
        }
      }
    }
    for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    {
      if (p->state == RUNNABLE && p->priority==min_prior)
      {
        plist[rr_count]=p;
        rr_count++;
      }
    }

    for (int i=0; i<rr_count; i++)
    {
      p=plist[i];
      if (p->state != RUNNABLE)
        continue;

      // Switch to chosen process.  It is the process's job
      // to release ptable.lock and then reacquire it
      // before jumping back to us.
      p->n_run++;
      c->proc = p;
      switchuvm(p);
      p->state = RUNNING;

      swtch(&(c->scheduler), p->context);
      switchkvm();

      // Process is done running for now.
      // It should have changed its p->state before coming back.
      c->proc = 0;
    }

    release(&ptable.lock);
  }

  #else

  #ifdef MLFQ
  
  struct proc *p;
  struct cpu *c = mycpu();
  c->proc = 0;

  

  for (;;)
  {
    // Enable interrupts on this processor.
    sti();
    int should_run=0;
    // Loop over process table looking for process to run.
    acquire(&ptable.lock);
    aging();
    for(int i=0;i<5;i++)
    {
      if(q_arr[i]==0)
      {
        continue;
      }

      struct pqueue *pq = q_arr[i];

      int runnable_proc=0;

      while(pq->next!=0)
      {
        if(pq->proc->state==RUNNABLE)
        {
          runnable_proc=1;
        }
        pq=pq->next;
      }
      if(pq->proc->state==RUNNABLE)
      {
        runnable_proc=1;
      }
      if(runnable_proc==0)
      {
        continue;
      }

      for (; pq != 0; pq = pq->back)
      {
        p=pq->proc;
        if (p->state == RUNNABLE)
        {
          should_run=1;
          break;
        }
      }
      if(should_run==1)
      {
        break;
      }
    }
    if(should_run==1)
    {
      // Switch to chosen process.  It is the process's job
      // to release ptable.lock and then reacquire it
      // before jumping back to us.
      if (p->burst[p->cur_q] == 0)
      {
        p->n_run++;
      }

      c->proc = p;
      switchuvm(p);
      p->state = RUNNING;

      swtch(&(c->scheduler), p->context);
      switchkvm();

      // HAVE TO MAKE IT WAIT FOR 2^CUR_Q

      // Process is done running for now.
      // It should have changed its p->state before coming back.
      c->proc = 0;
    }
    release(&ptable.lock);
  }

  #endif
  #endif
  #endif
  #endif
}

// Enter scheduler.  Must hold only ptable.lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->ncli, but that would
// break in the few places where a lock is held but
// there's no process.
void
sched(void)
{
  int intena;
  struct proc *p = myproc();

  if(!holding(&ptable.lock))
    panic("sched ptable.lock");
  if(mycpu()->ncli != 1)
    panic("sched locks");
  if(p->state == RUNNING)
    panic("sched running");
  if(readeflags()&FL_IF)
    panic("sched interruptible");
  intena = mycpu()->intena;
  swtch(&p->context, mycpu()->scheduler);
  mycpu()->intena = intena;
}

// Give up the CPU for one scheduling round.
void
yield(void)
{
  acquire(&ptable.lock);  //DOC: yieldlock
  myproc()->state = RUNNABLE;
  sched();
  release(&ptable.lock);
}

// A fork child's very first scheduling by scheduler()
// will swtch here.  "Return" to user space.
void
forkret(void)
{
  static int first = 1;
  // Still holding ptable.lock from scheduler.
  release(&ptable.lock);

  if (first) {
    // Some initialization functions must be run in the context
    // of a regular process (e.g., they call sleep), and thus cannot
    // be run from main().
    first = 0;
    iinit(ROOTDEV);
    initlog(ROOTDEV);
  }

  // Return to "caller", actually trapret (see allocproc).
}

// Atomically release lock and sleep on chan.
// Reacquires lock when awakened.
void
sleep(void *chan, struct spinlock *lk)
{
  struct proc *p = myproc();
  
  if(p == 0)
    panic("sleep");

  if(lk == 0)
    panic("sleep without lk");

  // Must acquire ptable.lock in order to
  // change p->state and then call sched.
  // Once we hold ptable.lock, we can be
  // guaranteed that we won't miss any wakeup
  // (wakeup runs with ptable.lock locked),
  // so it's okay to release lk.
  if(lk != &ptable.lock){  //DOC: sleeplock0
    acquire(&ptable.lock);  //DOC: sleeplock1
    release(lk);
  }
  // Go to sleep.
  p->chan = chan;
  p->state = SLEEPING;

  sched();

  // Tidy up.
  p->chan = 0;

  // Reacquire original lock.
  if(lk != &ptable.lock){  //DOC: sleeplock2
    release(&ptable.lock);
    acquire(lk);
  }
}

//PAGEBREAK!
// Wake up all processes sleeping on chan.
// The ptable lock must be held.
static void
wakeup1(void *chan)
{
  struct proc *p;

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++)
  {
    if(p->state == SLEEPING && p->chan == chan)
    { 
      #ifdef MLFQ
      // cprintf("1\n");
      p->mlfq_wait=0;
      p->burst[p->cur_q] = 0;

      struct pqueue *pq = p->qnode;

      if (pq->proc != p)
      {
        cprintf("ERROR: wakeup1: failed to find process in process queue\n");
      }
      else if (pq->back!=0)
      {
        // cprintf("2\n");
        pq->back->next = pq->next;
        if(pq->next!=0)
        {
          pq->next->back=pq->back;
        }
        pq->back = 0;
        pq->next = q_arr[p->cur_q];
        if(q_arr[p->cur_q]!=0)
        {
          q_arr[p->cur_q]->back = pq;
        }
        q_arr[p->cur_q] = pq;
        // cprintf("3\n");
      }
      #endif
      // cprintf("4\n");
      p->state = RUNNABLE;
    }
  }
}

// Wake up all processes sleeping on chan.
void
wakeup(void *chan)
{
  acquire(&ptable.lock);
  wakeup1(chan);
  release(&ptable.lock);
}

// Kill the process with the given pid.
// Process won't exit until it returns
// to user space (see trap in trap.c).
int
kill(int pid)
{
  struct proc *p;

  acquire(&ptable.lock);
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->pid == pid){
      p->killed = 1;
      // Wake process from sleep if necessary.
      if(p->state == SLEEPING)
        p->state = RUNNABLE;
      release(&ptable.lock);
      return 0;
    }
  }
  release(&ptable.lock);
  return -1;
}

//PAGEBREAK: 36
// Print a process listing to console.  For debugging.
// Runs when user types ^P on console.
// No lock to avoid wedging a stuck machine further.
void
procdump(void)
{
  static char *states[] = {
  [UNUSED]    "unused",
  [EMBRYO]    "embryo",
  [SLEEPING]  "sleep ",
  [RUNNABLE]  "runble",
  [RUNNING]   "run   ",
  [ZOMBIE]    "zombie"
  };
  int i;
  struct proc *p;
  char *state;
  uint pc[10];

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->state == UNUSED)
      continue;
    if(p->state >= 0 && p->state < NELEM(states) && states[p->state])
      state = states[p->state];
    else
      state = "???";
    cprintf("%d %s %s", p->pid, state, p->name);
    if(p->state == SLEEPING){
      getcallerpcs((uint*)p->context->ebp+2, pc);
      for(i=0; i<10 && pc[i] != 0; i++)
        cprintf(" %p", pc[i]);
    }
    cprintf("\n");
  }
}

void
aging(void)
{
  for (struct proc *p = ptable.proc; p < &ptable.proc[NPROC]; p++)
  {
    if(p->state==RUNNABLE)
    {
      int age_limit=40;
      if(p->mlfq_wait > age_limit)
      {
        p->mlfq_wait=0;
        int init_q=p->cur_q;
        if(init_q>0)
        {
          p->burst[p->cur_q]=0;
          p->cur_q--;
        }
        p->burst[p->cur_q]=0;

        cprintf("\nGRAPH %d %d %d\n", p->pid, p->cur_q, ticks);

        if(init_q>0)
        {
          struct pqueue * pq = p->qnode;

          if(pq->back==0)
          {
            q_arr[init_q]=pq->next;
            if(pq->next!=0)
            {
              pq->next->back=0;
            }
            pq->back=0;
            pq->next=q_arr[p->cur_q];
            if(pq->next!=0)
            {
              pq->next->back=pq;
            }
            q_arr[p->cur_q]=pq;
          }
          else
          {
            pq->back->next=pq->next;
            if(pq->next!=0)
            {
              pq->next->back=pq->back;
            }
            pq->back=0;
            pq->next=q_arr[p->cur_q];
            if(pq->next!=0)
            {
              pq->next->back=pq;
            }
            q_arr[p->cur_q]=pq;
          }
        }
      }
    }
  }
}

void
timeslice(void)
{
  int burst_max[5]={1,2,4,8,16};
  for (struct proc *p = ptable.proc; p < &ptable.proc[NPROC]; p++)
  {
    if (p->state == RUNNING)
    {
      if(p->burst[p->cur_q]>burst_max[p->cur_q])
      {
        // cprintf("\n\nPROCESS %d DEMOTED\n\n\n",p->pid);
        int init_q = p->cur_q;
        p->burst[p->cur_q]=0;
        if(init_q<4)
        {
          p->cur_q++;
          p->burst[p->cur_q]=0;
          cprintf("\nGRAPH %d %d %d\n", p->pid, p->cur_q, ticks);

          struct pqueue *pq = p->qnode;

          if (pq->back == 0)
          {
            q_arr[init_q] = pq->next;
            if (pq->next != 0)
            {
              pq->next->back = 0;
            }
            pq->back = 0;
            pq->next = q_arr[p->cur_q];
            if (pq->next != 0)
            {
              pq->next->back = pq;
            }
            q_arr[p->cur_q] = pq;
          }
          else
          {
            pq->back->next = pq->next;
            if (pq->next != 0)
            {
              pq->next->back = pq->back;
            }
            pq->back = 0;
            pq->next = q_arr[p->cur_q];
            if (pq->next != 0)
            {
              pq->next->back = pq;
            }
            q_arr[p->cur_q] = pq;
          }
        }
        else
        {
          struct pqueue *pq = p->qnode;
          cprintf("\nGRAPH %d %d %d\n", p->pid, p->cur_q, ticks);
          if(pq->back!=0)
          {
            pq->back->next=pq->next;
            if(pq->next!=0)
            {
              pq->next->back=pq->back;
            }
            pq->back=0;
            pq->next=q_arr[p->cur_q];
            if(pq->next!=0)
            {
              pq->next->back=pq;
            }
            q_arr[p->cur_q] = pq;
          }
        }
      }
    }
  }
}

int
inc_rtime(void)
{
  // psys();
  acquire(&ptable.lock);
  for(struct proc* p = ptable.proc; p < &ptable.proc[NPROC]; p++)
  {
    if(p->state==RUNNING)
    {
      p->rtime++;
    }
    else if(p->state==SLEEPING)
    {
      p->sleep_time++;
    }
    #ifdef MLFQ
    if(p->state==RUNNABLE)
    {
      p->mlfq_wait++;
    }
    else if(p->state==RUNNING)
    {
      p->q[p->cur_q]++;
      p->burst[p->cur_q]++;
    }
    timeslice();
    // if(p->state==RUNNABLE)
    // {
    //   p->mlfq_wait++;

    //   int age_limit = 20;
    //   if(p->mlfq_wait>=age_limit)      //aging
    //   {
    //     int init_q = p->cur_q;
    //     if(p->cur_q>0)
    //     {
    //       p->cur_q--;
    //       p->burst[p->cur_q + 1] = 0;
    //     }
    //     p->burst[p->cur_q] = 0;

    //     struct pqueue *pq = p->qnode;

    //     if (pq->proc != p)
    //     {
    //       cprintf("ERROR: inc_rtime: failed to find process in process queue\n");
    //     }
    //     // else if (pq->back!=0 && p->cur_q==0)
    //     // {
    //     //   pq->back->next = pq->next;
    //     //   pq->back = 0;
    //     //   if(pq->next!=0)
    //     //   {
    //     //     pq->next->back=pq->back;
    //     //   }
    //     //   pq->next = q_arr[p->cur_q];
    //     //   q_arr[p->cur_q]->back = pq;
    //     //   q_arr[p->cur_q] = pq;
    //     // }
    //     else if (init_q>0)
    //     {
    //       if(pq->back==0)
    //       {
    //         q_arr[p->cur_q+1]=pq->next;
    //         if (pq->next != 0)
    //         {
    //           pq->next->back = pq->back;
    //         }
    //         pq->next = q_arr[p->cur_q];
    //         if(q_arr[p->cur_q]!=0)
    //         {
    //           q_arr[p->cur_q]->back=pq;
    //         }
    //         q_arr[p->cur_q] = pq;
    //       }
    //       else
    //       {
    //         pq->back->next = pq->next;
    //         pq->back=0;
    //         if(pq->next!=0)
    //         {
    //           pq->next->back=pq->back;
    //         }
    //         pq->next = q_arr[p->cur_q];
    //         if (q_arr[p->cur_q] != 0)
    //         {
    //           q_arr[p->cur_q]->back = pq;
    //         }
    //         q_arr[p->cur_q] = pq;
    //       }
    //     }
    //   }
    // }
    // else if(p->state==RUNNING)
    // {
    //   p->q[p->cur_q]++;
    //   p->burst[p->cur_q]++;
    //   int burst_max[5] = {1,2,4,8,16};
    //   if(p->burst[p->cur_q]>=burst_max[p->cur_q])
    //   {
    //     p->mlfq_wait=0;
    //     if(p->cur_q<4)
    //     {
    //       struct pqueue *pq = p->qnode;
    //       p->cur_q++;
    //       p->burst[p->cur_q - 1]=0;
    //       p->burst[p->cur_q] = 0;


    //       if(pq->proc!=p)
    //       {
    //         cprintf("ERROR: inc_rtime: failed to find process in process queue\n");
    //       }
    //       else
    //       {
    //         if (pq->back == 0)
    //         {
    //           q_arr[p->cur_q - 1] = pq->next;
    //           if (pq->next != 0)
    //           {
    //             pq->next->back = pq->back;
    //           }
    //           // pq->back = 0;
    //           pq->next = q_arr[p->cur_q];
    //           if (q_arr[p->cur_q] != 0)
    //           {
    //             q_arr[p->cur_q]->back = pq;
    //           }
    //           q_arr[p->cur_q] = pq;
    //         }
    //         // if(pq->back!=0)
    //         else
    //         {
    //           pq->back->next = pq->next;
    //           pq->back = 0;
    //           if (pq->next != 0)
    //           {
    //             pq->next->back = pq->back;
    //           }
    //           pq->next = q_arr[p->cur_q];
    //           if (q_arr[p->cur_q] != 0)
    //           {
    //             q_arr[p->cur_q]->back = pq;
    //           }
    //           q_arr[p->cur_q] = pq;
    //         }
    //       }
    //     }
    //     else if (p->cur_q == 4)
    //     {
    //       p->burst[p->cur_q] = 0;

    //       struct pqueue *pq = p->qnode;
    //       if (pq->proc != p)
    //       {
    //         cprintf("ERROR: inc_rtime: failed to find process in process queue\n");
    //       }
    //       else if (pq->back!=0)
    //       {
    //         pq->back->next = pq->next;
    //         if(pq->next!=0)
    //         {
    //           pq->next->back=pq->back;
    //         }
    //         pq->back = 0;
    //         pq->next = q_arr[p->cur_q];
    //         if (q_arr[p->cur_q]!=0)
    //         {
    //           q_arr[p->cur_q]->back = pq;
    //         }
    //         q_arr[p->cur_q] = pq;
    //       }
    //     }
    //   }
    // }
    
    #endif
  }
  release(&ptable.lock);
  return 0;
}