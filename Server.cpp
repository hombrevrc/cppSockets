#include <tpf/tpfeq.h>
#include <tpf/tpfio.h>

#include <stdio.h>
#include <stdlib.h>

#include <sys/socket.h>           /* Socket API Header File */
#include <sys/types.h>

#define IP "9.57.13.156"

#define PORT "1111"


void QSSM(void)
{
   int servfd;
   struct sockaddr_in server;
   unsigned char aoapgm[4]={'Q','S','S','L'};
   unsigned char aoaparm[8];

   servfd=socket(AF_INET,SOCK_STREAM,0);
   server.sin_family=AF_INET;
   server.sin_addr.s_addr=inet_addr(IP);
   server.sin_port=atoi(PORT);

   bind(servfd,(struct sockaddr*) &server
        ,sizeof(server));

   listen(servfd,5);

   printf("activated socket\n");

   activate_on_accept(servfd,aoaparm,aoapgm,0); 

   exit(0);
}
