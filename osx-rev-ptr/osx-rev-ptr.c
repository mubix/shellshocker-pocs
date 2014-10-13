/*  See the CVE-2014-3671  advisory.
 *
 * Copyright 2014 Dirk-Willem van Gulik, All Rights Reserved.
 *                <dirkx(at)webweaving.org>,
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


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

