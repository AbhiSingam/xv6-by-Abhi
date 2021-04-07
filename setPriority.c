#include "types.h"
#include "stat.h"
#include "user.h"

int main(int argc, char *argv[])
{
    int priority;
    int pid;
    if (argc < 3)
    {
        printf(2,"ERROR: setPriority: Insufficient nuber of arguments\n");
        exit();
    }

    priority = atoi(argv[1]);
    pid = atoi(argv[2]);

    int old_pr = set_priority(priority,pid);

    printf(1,"Priority of process with pid %d changed from %d to %d\n",pid,old_pr,priority);
    exit();
}