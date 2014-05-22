#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXLINE   4096
#define SERV_PORT 11111

/*send and recieve message function */
void DatagramClient (FILE* clientInput, int sockfd, 
                     const struct sockaddr* pServAddr, socklen_t servLen){

    int     n;
    char    sendLine[MAXLINE], recvLine[MAXLINE +1];

    while (fgets(sendLine, MAXLINE, clientInput) != NULL) {
        
       if ( ( sendto(sockfd, sendLine, strlen(sendLine) - 1, 0, pServAddr, 
              servLen)) == -1) {
            perror("error in sending");
        }


       if ( (n = recvfrom(sockfd, recvLine, MAXLINE, 0, NULL, NULL)) == -1) {
             perror("Error in receiving");   
        }

        recvLine[n] = 0;  
        fputs(recvLine, stdout);
    }
}

int main(int argc, char** argv){

    int 	sockfd;
    struct 	sockaddr_in servAddr;
    
    if (argc != 2) {
        perror("usage: udpcli <IP address>\n");
        exit(1);
    }

    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
       perror("cannot create a socket.");
       exit(1);
    } 

    bzero(&servAddr, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(SERV_PORT);
    inet_pton(AF_INET, argv[1], &servAddr.sin_addr);

    DatagramClient(stdin, sockfd, (struct sockaddr*) &servAddr, 
                   sizeof(servAddr));

    return 0;
}
