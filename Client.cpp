// C++ SMTP STARTTLS Command
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// socket time out
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
// get host by address
#include <netdb.h>
#define PORT 25

int main(int argc, char const *argv[])
{
    int sock = 0, valread;
    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname((char *)"aspmx.l.google.com")) == NULL)
    {
        perror("Hostname error");
        abort();
    }

    if ((sock = socket(AF_INET, SOCK_STREAM,0))<0)
    {
        printf("\n Socket creation error \n");
        return -1;
    }
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        printf("\nConnection Failed \n");
        return -1;
    }else{
        printf("Connected !!!");
    }

    char buffer[1024] = {0};
    char *hello = (char*)"EHLO qflash.pl\r\n";
    char *hellotls = (char*)"STARTTLS\r\n";
    
    // Read from server 220 mx.host
    valread = read(sock,buffer,8192);
    printf("Server : %s\n",buffer);
    
    // Send EHLO
    send(sock,hello,strlen(hello),0);
    printf("Hello message sent\n");    
    valread = read(sock,buffer,8192);
    printf("%s\n",buffer);
    
    // Send STARTTLS
    send(sock,hellotls,strlen(hellotls),0);
    printf("STARTTLS message sent\n");    
    valread = read(sock,buffer,8192);
    printf("%s\n",buffer);
    
    // START TLS CONNECTION HERE //
    
    return 0;
 }
