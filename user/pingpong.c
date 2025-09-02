#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
    int p1[2];  
    int p2[2];  
    char buffer[1];
    int pid;
    
    if (pipe(p1) < 0 || pipe(p2) < 0) {
        fprintf(2, "pipe creation failed\n");
        exit(1);
    }
    
    pid = fork();
    if (pid < 0) {
        fprintf(2, "fork failed\n");
        exit(1);
    }
    
    if (pid == 0) {  
        close(p1[1]); 
        close(p2[0]);  
        
        if (read(p1[0], buffer, sizeof(buffer)) != 1) {
            fprintf(2, "child read error\n");
            exit(1);
        }
        close(p1[0]);
        
        printf("%d: received ping\n", getpid());
     
        if (write(p2[1], buffer, 1) != 1) {
            fprintf(2, "child write error\n");
            exit(1);
        }
        close(p2[1]);
        
        exit(0);
    } else {
        close(p1[0]);  
        close(p2[1]);  
        
        buffer[0] = 'X';
        if (write(p1[1], buffer, 1) != 1) {
            fprintf(2, "parent write error\n");
            exit(1);
        }
        close(p1[1]);
        
        wait(0);
        
        if (read(p2[0], buffer, sizeof(buffer)) != 1) {
            fprintf(2, "parent read error\n");
            exit(1);
        }
        close(p2[0]);
        
        printf("%d: received pong\n", getpid());
        
        exit(0);
    }
}
