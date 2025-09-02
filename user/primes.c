#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
void primes(int read_fd) __attribute__((noreturn));
void primes(int read_fd)
{
	int prime;
	int num;
	int p[2];
	if(read(read_fd,&prime,sizeof(prime))!=sizeof(prime))
	{
		close(read_fd);
		exit(0);
	}
	printf("prime %d\n",prime);
	if(pipe(p)<0)
	{
		fprintf(2,"管道创建失败\n");
		exit(1);
	}
	int pid=fork();
	if(pid==0)
	{
		close(read_fd);
		close(p[1]);
		primes(p[0]);
	}
	else {
		close(p[0]);
                

		while(read(read_fd,&num,sizeof(num))==sizeof(num))
		{
			if(num%prime != 0)
			{
				if(write(p[1],&num,sizeof(num))!=sizeof(num))
				{
                                        fprintf(2,"write error\n");
					exit(0);
				}
			}
		}
		close(read_fd);
		close(p[1]);
		wait(0);
		exit(0);
	}
}
int main(int argc,char *argv[])
{
    int p[2];
    if(pipe(p)<0)
    {
        fprintf(2,"管道创建失败\n");
	exit(1);
    }
    int pid=fork();
    if(pid==0)
    {
        close(p[1]);
	primes(p[0]);
    }
    else {
	    for(int i=2;i<=280;i++){
		    if(write(p[1],&i,sizeof(i))!=sizeof(i))
		    {
			    fprintf(2,"写入失败\n");
			    exit(1);
		    }
	    }
	    close(p[1]);
	    wait(0);
	    exit(0);
    }
    return 0;
}
