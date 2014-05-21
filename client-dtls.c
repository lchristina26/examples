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
#define MAXLINE 4096
#define SERV_PORT 11111 

void err_sys (const char* x) {
    perror(x);
    exit(1);
}

void sig_handler (const int sig) {
    printf("\nSIGINT handled.\n");
    CyaSSL_Cleanup();
    exit(EXIT_SUCCESS);
}

void DatagramClient (FILE* clientInput, CYASSL* ssl) {

    int     n = 0;
    char    sendLine[MAXLINE], recvLine[MAXLINE - 1];

    while (fgets(sendLine, MAXLINE, clientInput) != NULL) {
        
       if ( ( CyaSSL_write(ssl, sendLine, strlen(sendLine))) != strlen(sendLine)){
            err_sys("SSL_write failed");
        }

       n = CyaSSL_read(ssl, recvLine, sizeof(recvLine)-1);
       
       if (n < 0){
            int readErr = CyaSSL_get_error(ssl, 0);
	    if(readErr != SSL_ERROR_WANT_READ)
		err_sys("CyaSSL_read failed");
       }

        recvLine[n] = '\0';  
        fputs(recvLine, stdout);

    }
}

int main (int argc, char** argv) {

    int     	sockfd = 0;
    struct  	sockaddr_in servAddr;
    const char* host = argv[1];
    CYASSL* 	ssl = 0;
    CYASSL_CTX* ctx = 0;

    if (argc != 2) {
        perror("usage: udpcli <IP address>\n");
        exit(1);
    }

    CyaSSL_Init();
    CyaSSL_Debugging_ON();
   
    if ( (ctx = CyaSSL_CTX_new(CyaDTLSv1_2_client_method())) == NULL){
        fprintf(stderr, "CyaSSL_CTX_new error.\n");
        exit(EXIT_FAILURE);
    }

    if (CyaSSL_CTX_load_verify_locations(ctx,"../cyassl/certs/ca-cert.pem",0) != SSL_SUCCESS) {
        fprintf(stderr, "Error loading ../certs/ca-cert.pem, please check the file.\n");
        exit(EXIT_FAILURE);
    }

    ssl = CyaSSL_new(ctx);
    if (ssl == NULL)
    	err_sys("unable to get ssl object");
    
    bzero(&servAddr, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(SERV_PORT);
    inet_pton(AF_INET, host, &servAddr.sin_addr);

    CyaSSL_dtls_set_peer(ssl, &servAddr, sizeof(servAddr));

    
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
       err_sys("cannot create a socket."); 

    signal(SIGINT, sig_handler);

/*    int err = connect(sockfd, (struct sockaddr*) &servAddr, sizeof(servAddr));
*    if(err < 0)
*       err_sys("Connect error");
*/    
    CyaSSL_set_fd(ssl, sockfd);
    if (CyaSSL_connect(ssl) != SSL_SUCCESS){
	int err1 = CyaSSL_get_error(ssl, 0);
	char buffer[80];
	printf("err = %d, %s\n", err1, CyaSSL_ERR_error_string(err1, buffer));
	err_sys("SSL_connect failed");
    }
 
    DatagramClient(stdin, ssl);
    CyaSSL_shutdown(ssl);
    CyaSSL_free(ssl);
    CyaSSL_CTX_free(ctx);
    CyaSSL_Cleanup();

    return 0;
}
