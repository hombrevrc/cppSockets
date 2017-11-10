// Connect:
// openssl s_client -connect localhost:999
// Compile
// g++ ssl.cpp -std=c++11 -lssl -lcrypto -o start
// install libssl-dev openssl

// dkim signer pdkim
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
// timestamp time.h
#include <ctime>
// cout, cin
#include <iostream>
// file
#include <fstream>
#include <sstream>      // std::ostringstream
#include <algorithm>
#include <stdio.h>
#include <cstdio>
#include <unistd.h>
#include <string>
#include <cstring>
#include <sstream>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

//email validate
#include <regex>
// mkdir
#include <sys/types.h>
#include <sys/stat.h>
// current dir
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <netdb.h>

// sslclient
// #include <sslclient.h>
// #include <pthread.h>
#include <thread>
// #include <errno.h>

// pid proccess kill signals
#include <signal.h>

#define MAX_LINE_LEN 1024000

using namespace std;

void sslError(SSL *ssl, int received){
    const int err = SSL_get_error(ssl, received);
    // const int st = ERR_get_error();
    if (err == SSL_ERROR_NONE) {
        // OK send
        // std::cout << "[SSL_OK] " << err << endl;
    } else if (err == SSL_ERROR_WANT_READ ) {
        SSL_shutdown(ssl);
        kill(getpid(), SIGKILL);
    } else if (err == SSL_ERROR_SYSCALL) {
        SSL_shutdown(ssl);
        kill(getpid(), SIGKILL);
    } else if (err == SSL_ERROR_ZERO_RETURN) {
        SSL_shutdown(ssl);
        kill(getpid(), SIGKILL);
    } else if (err == SSL_ERROR_SSL) {
        SSL_shutdown(ssl);
        kill(getpid(), SIGKILL);
    } else {
        SSL_shutdown(ssl);
        kill(getpid(), SIGKILL);
    }
}

void ShowCerts(SSL* ssl) {   X509 *cert;
    char *line;
    /* Get certificates (if available) */
    cert = SSL_get_peer_certificate(ssl);
    if ( cert != NULL )
    {
        cout << "Server certificates:" << endl;
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        cout << "Subject: " << line << endl;
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        cout << "Issuer: " << line << endl;
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}

void socket_timeout(int sec, int sock){
    struct timeval timeout;      
    timeout.tv_sec = sec;
    timeout.tv_usec = 0;
    // (const char*)
    if (setsockopt (sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0){
        cout << "Timeout set failed" << endl;
    }

    if (setsockopt (sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0){
        cout << "Timeout set failed" << endl;
    }
}

int create_socket(int port) {
    int s;
    int opt = 1;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        cout << "Unable to create socket" << endl;
        exit(EXIT_FAILURE);
    }

    // Add socket time out (only if not multiple threads)
    // socket_timeout(10, s);

    //set master socket to allow multiple connections
    if( setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0 ) {
        cout << "setsockopt" << endl;
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        cout << "Unable to bind" << endl;
        exit(EXIT_FAILURE);
    }

    if (listen(s, 5) < 0) {
        cout << "Unable to listen" << endl;
        exit(EXIT_FAILURE);
    }
    return s;
}

void init_openssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    ERR_load_crypto_strings();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    method = SSLv23_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        cout << "Unable to create SSL context" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    // Renegotiation
    // SSL_CTX_set_options(ctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);

    return ctx;
}

void configure_context(SSL_CTX *ctx, std::string Certificate, std::string CertificateKey)
{
    // SSL_CTX_set_ecdh_auto(ctx, 1);
    
    /*Load the password for the Private Key if any */
    // SSL_CTX_set_default_passwd_cb_userdata(ctx,KEY_PASSWD);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, Certificate.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }    

    if (SSL_CTX_use_PrivateKey_file(ctx, CertificateKey.c_str(), SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /*Make sure the key and certificate file match*/
    if (SSL_CTX_check_private_key(ctx) == 0) {
        printf("Private key does not match the certificate public key\n");
        exit(EXIT_FAILURE);
    }

    /*Used only if client authentication will be used*/
    // SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,NULL);

}

void ServerLoop(SSL *ssl, string ipAddress){
	// IP address
	const string SenderIP = ipAddress;

	// buffer
	const int readSize = 8192;
    char buffer[readSize];
    // recived bytes
    int received;
    // total bytes
    int TotalReceived = 0;

    while(1){
    	// do send/read loop here

    	// clear buffer 
        memset(buffer, 0, sizeof buffer);
        buffer[0] = '\0';

        // Read from client
        received = SSL_read (ssl, buffer, sizeof(buffer));

        // get error
        sslError(ssl, received);

        // Count total bytes
        TotalReceived += received;
        
        // Message
        char reply[] = "Hello from server\r\n";

        // Send message
        received = SSL_write(ssl, reply, strlen(reply));

        // get error
        sslError(ssl, received);
    }
}

// Date time like smtp date
char * currentDateTimeSMTP(){
    // current date/time based on current system
   time_t now = time(0);   
   // convert now to string form
   char* dt = ctime(&now);   
   dt[strlen(dt)-1] = '\0';
   return dt;
}

unsigned long getMicrotime(){  
    struct timeval tp;
    gettimeofday(&tp, NULL);
    long int ms = tp.tv_sec * 1000 + tp.tv_usec / 1000; 
    // cout << ms << " microseconds " << endl;
    return ms;
}

string getCurrentDir()
{
   char * dir = get_current_dir_name();
   return string(dir);
}

int Port = 999;

int main(){
    int sock;
    SSL_CTX *ctx;

	try{
		// Initialize ssl
	    SSL_library_init();	    
	    // Init ssl
	    init_openssl();
	    // Create context
	    ctx = create_context();
	    // Configure
	    configure_context(ctx, "certificate.pem", "private.key");    
	    // Create socket
	    sock = create_socket(Port);
	    // socket descriptor	
	    int client;
	    // ip address
	    struct sockaddr_in addr;
	    uint len = sizeof(addr);              

        while(1){

	        cout << "Waiting for connections ..." << endl;
	        client = accept(sock, (struct sockaddr*)&addr, &len);
	        // Get remote ip address
	        string SenderClientIP = inet_ntoa(addr.sin_addr); 

	        if(client < 0){
	        	cout << "Error socket" << endl;
	        }else{

	        	// Add timeout in seconds to child socket
	        	socket_timeout(10, client);

	        	// thread pid (create new proccess for new client)
	            pid_t pid;
	            int currpid = 0 ;
	            
	            /*
				// Threads array (ile tredów) c++11
				std::thread t[num_threads];
				//Launch a group of threads with server host name		
				for (int i = 0; i < num_threads; i++) { 
					// Run new thread
					t[i] = std::thread(boo,i,serverHost,sendLimit,settings[1],settings[2],settings[3],settings[4],"breakermindsmtp"); 
				}
				// join but not needed
				// for (int i = 0; i < num_threads; ++i) { t[i].join(); }
	            */

	            // create child proccess with fork();
	            pid = fork();

	            // if pid > 0 (child proccess ok) if -1 error create new proccess
	            if(pid == -1){
	                cout << "[ERROR_FORK_CHILD]" << endl;
	            }else{
	                cout << "[FORK_CHILD] " << currentDateTimeSMTP() << endl;
	            }
	            
	            // if fork() create new proccess pid in child proccess == 0
	            if(pid == 0){
	            	// this doing only in child proccess
	            	int childPid = getpid();
	                cout << " [NEW_CONNECTION_PID]" << childPid << endl;
					
					SSL *ssl;
	                ssl = SSL_new(ctx);

	                // Renegotiation ssl
	                // SSL_set_options(ssl, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);

	                SSL_set_fd(ssl, client);
	                // ShowCerts(ssl);
	                if (SSL_accept(ssl) <= 0) {
	                    // SSL_get_error();
	                    ERR_print_errors_fp(stderr);                        
	                    cout << "[ERROR_TLS_HANDSHAKE]" << endl;
	                    SSL_free(ssl);
	                    close(client);
	                    kill(getpid(), SIGTERM);
	                    kill(getpid(), SIGKILL);                            
	                } else {
	                    // don't send anything                    
	                }

	                // Server loop recieved and send data from clients with fork();
	                ServerLoop(ssl,SenderClientIP);

	                // Close socket                    
	                SSL_free(ssl);
	                close(client);                
	                kill(getpid(), SIGTERM);
	                kill(getpid(), SIGKILL);

	            }
	        }
		
		}// end while

	    // close(sock);
	    SSL_CTX_free(ctx);
	    cleanup_openssl();

    }catch(...){
    	cout << "Error ..." << endl;
    }	
}
