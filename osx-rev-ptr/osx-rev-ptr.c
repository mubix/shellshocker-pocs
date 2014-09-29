#include <sys/socket.h>
#include <netdb.h>
#include <assert.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>

int main(int argc, char ** argv) {
	struct in_addr addr;
	struct sockaddr_in sa;
	char host[1024];

	assert(argc==2);
	assert(inet_aton(argv[1],&addr) == 1);

	sa.sin_family = AF_INET;
	sa.sin_addr = addr;

	assert(0==getnameinfo((struct sockaddr *)&sa, sizeof sa,
		host, sizeof host, NULL, 0, NI_NAMEREQD));

	printf("Lookup result: %s\n\n", host);    

	assert(setenv("REMOTE_HOST",host,1) == 0);
	execl("/bin/bash",NULL);
}

