#include <tpf/tpfeq.h>
#include <tpf/tpfio.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

/* define HOME to be dir for key and certificate files... */
#define HOME "/certs/"
/* Make these what you want for certificate & key files */
#define CERT_FILE  HOME "1024ccert.pem"
#define KEY_FILE  HOME  "1024ckey.pem"

/*Cipher list to be used*/
#define CIPHER_LIST "AES128-SHA"

/*Trusted CAs location*/
#define CA_FILE "/certs/1024ccert.pem"
#define CA_DIR  NULL

/*Password for the key file*/
#define KEY_PASSWD "keypass"

#define IP "9.57.13.156"

#define PORT "1111"


void QSSN(void)
{
int socketfd;
int err, count;
char buff[32];
struct sockaddr_in socketaddr;

/*SSL PART*/
SSL_METHOD *meth;
SSL_CTX *ctx;
SSL *myssl;

socketfd=socket(AF_INET,SOCK_STREAM,0);

socketaddr.sin_family=AF_INET;
socketaddr.sin_addr.s_addr=inet_addr(IP);
socketaddr.sin_port=atoi(PORT);

/* SSL Part*/
SSL_library_init();
SSL_load_error_strings();

meth=SSLv23_client_method();

/*Create a new context block*/
ctx=SSL_CTX_new(meth);
if (!ctx) {
   printf("Error creating the context.\n");
   exit(0);
}

/*Set cipher list*/
if (SSL_CTX_set_cipher_list(ctx,CIPHER_LIST) <= 0) {
printf("Error setting the cipher list.\n");
   exit(0);
}

/*Indicate the certificate file to be used*/
if (SSL_CTX_use_certificate_file(ctx,CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
   printf("Error setting the certificate file.\n");
   exit(0);
}

/*Load the password for the Private Key*/
SSL_CTX_set_default_passwd_cb_userdata(ctx,KEY_PASSWD);

/*Indicate the key file to be used*/
if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
   printf("Error setting the key file.\n");
   exit(0);
}

/*Make sure the key and certificate file match*/
if (SSL_CTX_check_private_key(ctx) == 0) {
   printf("Private key does not match the certificate public key\n");
   exit(0);
}

/* Set the list of trusted CAs based on the file and/or directory provided*/
if(SSL_CTX_load_verify_locations(ctx,CA_FILE,CA_DIR)<1) {
   printf("Error setting verify location\n");
   exit(0);
}

/* Set for server verification*/
SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);

/*Create new ssl object*/
myssl=SSL_new(ctx);

if(!myssl) {
   printf("Error creating SSL structure.\n");
   exit(0);
}

/* Connect to the server, TCP/IP layer,*/
err=connect(socketfd,(struct sockaddr*)&socketaddr,sizeof(socketaddr));
if(err<0) {
   printf("Socket returned error #%d,program terminated\n",sock_errno());
   SSL_free(myssl);
   SSL_CTX_free(ctx);
   exit(0);
}

/*Bind the socket to the SSL structure*/
SSL_set_fd(myssl,socketfd);

/*Connect to the server, SSL layer.*/
err=SSL_connect(myssl);

/*Check for error in connect.*/
if (err<1) {
   err=SSL_get_error(myssl,err);
   printf("SSL error #%d in accept,program terminated\n",err);

   if(err==5){printf("sockerrno is:%d\n",sock_errno());}
  
   close(socketfd);
   SSL_free(myssl);
   SSL_CTX_free(ctx);
   exit(0);
}

/*Print out connection details*/
printf("SSL connection on socket %x,Version: %s, Cipher: %s\n",
       socketfd,
       SSL_get_version(myssl),
       SSL_get_cipher(myssl));

/*Send message to the server.*/
err=SSL_write(myssl,"Hello there!!!!",sizeof("Hello there!!!!")+1);
/*Check for error in write.*/
if(err<1) {
   err=SSL_get_error(myssl,err);
   printf("Error #%d in write,program terminated\n",err);
   /********************************/
   /* If err=6 it means the Server */
   /* issued an SSL_shutdown. You  */
   /* must respond with a shutdown */
   /* to complete a graceful       */
   /* shutdown                     */
   /********************************/
   if(err==6)
     SSL_shutdown(myssl);
   SSL_free(myssl);
   close(socketfd);
   SSL_CTX_free(ctx);
   exit(0);
}

/*Read servers response.*/
err = SSL_read (myssl, buff, sizeof(buff));
/*Check for error in read.*/
if(err<1) {
   err=SSL_get_error(myssl,err);
   printf("Error #%d in read,program terminated\n",err);
   /********************************/
   /* If err=6 it means the client */
   /* issued an SSL_shutdown. You */
   /* must respond with a shutdown */
   /* to complete a graceful */
   /* shutdown */
   /********************************/
   if(err==6)
     SSL_shutdown(myssl);
    SSL_free(myssl);
    close(socketfd);
    SSL_CTX_free(ctx);
    exit(0);
}

printf("Server said: %s\n",buff);

err=SSL_shutdown(myssl);
count = 1;
/***********************************/
/* Try SSL_shutdown() 5 times to   */
/* wait for the remote application */
/* to issue SSL_shutdown().        */
/***********************************/

while(err != 1) {
   err=SSL_shutdown(myssl);
   if(err != 1)
     count++;
   if (count == 5)
     break;
   sleep(1);
}

if(err<0)
   printf("Error in shutdown\n");
else if(err==1)
   printf("Client exited gracefully\n");

close(socketfd);
SSL_free(myssl);
SSL_CTX_free(ctx);
exit(0);
}
