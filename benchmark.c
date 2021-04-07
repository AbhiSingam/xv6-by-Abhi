
#include "types.h"
#include "user.h"

int number_of_processes = 4;

int main(int argc, char *argv[])
{
  int j;
  for (j = 0; j < number_of_processes; j++)
  {
    int pid = fork();
    if (pid < 0)
    {
      printf(1, "Fork failed\n");
      continue;
    }
    if (pid == 0)
    {
      volatile int i;
      for (volatile int k = 0; k < number_of_processes; k++)
      {
        if (k <= j)
        {
          sleep(200); //io time
        }
        else
        {
          for (i = 0; i < 100000000; i++)
          {
            ; //cpu time
          }
        }
        // psys();
      }
      printf(1, "Process: %d Finished\n", j);
      exit();
    }
    else{
        ;
      set_priority(100-(20+j),pid); // will only matter for PBS, comment it out if not implemented yet (better priorty for more IO intensive jobs)
    }
  }
  int wtime, rtime, tottime=0;
  for (j = 0; j < number_of_processes; j++)
  {
    waitx(&wtime,&rtime);
    tottime+=wtime;
    printf(1,"wait: %d, run: %d\n",wtime, rtime);
  }
  printf(1,"total: %d\n",tottime);
  exit();
}
