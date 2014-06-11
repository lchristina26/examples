#include <cyassl/ssl.h>
#include <cyassl/options.h>
#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXLINE   4096
#define SERV_PORT 11111 

void err_sys (const char* x) 
{
    printf("%s", x);
    exit(1);
}

void sig_handler (const int sig) 
{
    printf("\nSIGINT handled.\n");
    CyaSSL_Cleanup();
    exit(EXIT_SUCCESS);
}

/* Send and receive function */
void DatagramClient (FILE* clientInput, CYASSL* ssl) 
{
    int  n = 0;
    char sendLine[MAXLINE], recvLine[MAXLINE - 1];

    fgets(sendLine, MAXLINE, clientInput);
        
       if ( ( CyaSSL_write(ssl, sendLine, strlen(sendLine))) != 
	      strlen(sendLine)) {
            err_sys("SSL_write failed");
        }

       n = CyaSSL_read(ssl, recvLine, sizeof(recvLine)-1);
       
       if (n < 0) {
            int readErr = CyaSSL_get_error(ssl, 0);
	    if(readErr != SSL_ERROR_WANT_READ)
		err_sys("CyaSSL_read failed");
       }

        recvLine[n] = '\0';  
        fputs(recvLine, stdout);
}

int main (int argc, char** argv) 
{
    int     		sockfd = 0;
    struct  		sockaddr_in servAddr;
    const char* 	host = argv[1];
    CYASSL* 		ssl = 0;
    CYASSL_CTX* 	ctx = 0;
    CYASSL* 		sslResume = 0;
    CYASSL_SESSION*	session = 0;
    char*    		srTest = "testing session resume";

    if (argc != 2) 
        err_sys("usage: udpcli <IP address>\n");

    signal(SIGINT, sig_handler);

    CyaSSL_Init();
    /* CyaSSL_Debugging_ON(); */
   
    if ( (ctx = CyaSSL_CTX_new(CyaDTLSv1_2_client_method())) == NULL) {
        fprintf(stderr, "CyaSSL_CTX_new error.\n");
        exit(EXIT_FAILURE);
    }

    if (CyaSSL_CTX_load_verify_locations(ctx,"../cyassl/certs/ca-cert.pem",0) 
	!= SSL_SUCCESS) {
        fprintf(stderr, 
		"Error loading ../certs/ca-cert.pem, please check the file.\n");
        exit(EXIT_FAILURE);
    }

    ssl = CyaSSL_new(ctx);
    if (ssl == NULL)
    	err_sys("unable to get ssl object");
    
    memset(&servAddr, sizeof(servAddr), 0);
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(SERV_PORT);
    inet_pton(AF_INET, host, &servAddr.sin_addr);

    CyaSSL_dtls_set_peer(ssl, &servAddr, sizeof(servAddr));
    
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
       err_sys("cannot create a socket."); 
    
    CyaSSL_set_fd(ssl, sockfd);
    if (CyaSSL_connect(ssl) != SSL_SUCCESS) {
	    int err1 = CyaSSL_get_error(ssl, 0);
	    char buffer[80];
	    printf("err = %d, %s\n", err1, CyaSSL_ERR_error_string(err1, buffer));
	    err_sys("SSL_connect failed");
    }
    
    DatagramClient(stdin, ssl);
    CyaSSL_write(ssl, srTest, sizeof(srTest));
    session = CyaSSL_get_session(ssl);
    sslResume = CyaSSL_new(ctx);

    CyaSSL_shutdown(ssl);
    CyaSSL_free(ssl);
    close(sockfd);

    memset(&servAddr, sizeof(servAddr), 0);
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(SERV_PORT);
    inet_pton(AF_INET, host, &servAddr.sin_addr);

    CyaSSL_dtls_set_peer(sslResume, &servAddr, sizeof(servAddr));
   
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
       err_sys("cannot create a socket."); 
    
    CyaSSL_set_fd(sslResume, sockfd);
    CyaSSL_set_session(sslResume, session);

    if (CyaSSL_connect(sslResume) != SSL_SUCCESS) 
	    err_sys("SSL_connect failed");

    if(CyaSSL_session_reused(sslResume))
    	printf("reused session id\n");
    else
    	printf("didn't reuse session id!!!\n");
    
    DatagramClient(stdin, sslResume);
    CyaSSL_write(sslResume, srTest, sizeof(srTest));

    CyaSSL_shutdown(sslResume);
    CyaSSL_free(sslResume);
    close(sockfd);
    CyaSSL_CTX_free(ctx);
    CyaSSL_Cleanup();

    return 0;
}

