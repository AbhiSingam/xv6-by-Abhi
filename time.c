#include "types.h"
#include "user.h"

int main(int argc, char *argv[])
{
    int pid_fork, wtime, rtime;
    pid_fork=fork();

    if(pid_fork<0)
    {
        printf(2,"ERROR: time: fork failed\n");
    }
    else if(pid_fork==0)
    {
        exec(argv[1],argv+1);
        printf(2,"ERROR: exec failed when trying to execute %s\n",argv[1]);
    }
    else
    {
        waitx(&wtime,&rtime);
        printf(1,"\nWait Time: %d clock ticks\nRun Time: %d clock ticks\n",wtime,rtime);
    }
    exit();
}