#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/ptrace.h>
 
int main()
{
    pid_t pid;
    int count = 0;
    int waitstatus;
    int syscall_entry = 1;
 
    pid = fork();
    if (pid==0) {
        ptrace(PTRACE_TRACEME, NULL, NULL, NULL);
        execl("/bin/date", "date", NULL);
    }
    else if (pid>0) {
        wait(&waitstatus);
        while (1) {
 
            if (syscall_entry == 1) {
                count++;
                syscall_entry = 0;
            }
            else {
                syscall_entry = 1;
            }
 
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            wait(&waitstatus);

            if (WIFEXITED(waitstatus)) break;
        }
    }
    else {
        printf("fork error\n");
    }
    printf("Total number of syscalls: %d\n", count);
    return 0;
}