/*
 * CIS 457
 * Project 4
 * Client
 * Authors: David Lamar, Taylor Cargill
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#define BUFFER_SIZE 1500
#define MESSAGE_SIZE 256
#define OP_INIT 0x00
#define OP_BROADCAST 0x01

void * receive(void * cs);

int main(int argc, char **argv) {
	if (argc != 4) {
		printf("Wrong number of arguments; make sure you specify the following:\n");
		printf("\tIP Address\n");
		printf("\tPort Number\n");
		printf("\tUser name\n");
		return 1;
	}

	char * ipAddress = argv[1];
	int port = atoi(argv[2]);
	char * userName = argv[3];

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		printf("Could not open socket. Exiting,\n");
		return 1;
	}

	struct sockaddr_in serveraddr;
	serveraddr.sin_family      = AF_INET;
	serveraddr.sin_port        = htons(port);
	serveraddr.sin_addr.s_addr = inet_addr(ipAddress);
	
	int e = connect(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr));
	if (e < 0) {
		printf("There was an error connecting. Exiting.\n");
		return 1;
	}

	//Send init message
	char userAuth[257];
	userAuth[0] = OP_INIT;
	strcpy(userAuth + 1, userName);
	send(sockfd, userAuth, 257, 0);

	pthread_t pid;
	if (pthread_create(&pid, NULL, receive, &sockfd)) {
		fprintf(stderr, "Error creating thread...\n");
		return 1;
	}

	while (1) {
		printf("Enter a message: ");
		char line[MESSAGE_SIZE];	
		fgets(line, MESSAGE_SIZE, stdin);

		char message[MESSAGE_SIZE + 1];
		message[0] = OP_BROADCAST;
		strcpy(message + 1, line);

		send(sockfd, message, strlen(message) + 1, 0);
	}

	close(sockfd);

	return 0;
}

void * receive(void * cs) {
	printf("Started receive thread.\n");
	int clientSocket = *((int*)cs);
	char line[BUFFER_SIZE];
	while (1) {
		recv(clientSocket, line, BUFFER_SIZE, 0);
		printf("Got message from server: %s", line);
	}
}







