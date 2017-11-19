/*
 * CIS 457
 * Project 4
 * Client
 * Authors: David Lamar, Taylor Cargill
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define BUFFER_SIZE 1500
#define MESSAGE_SIZE 256
#define OP_INIT 0x00
#define OP_BROADCAST 0x01
#define OP_WHISPER 0x02
#define OP_CLIENT_LIST 0x03
#define OP_KICK_USER 0x04

void * receive(void * cs);
void processCommand(int sockfd, char * message);

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
		char line[MESSAGE_SIZE];	
		fgets(line, MESSAGE_SIZE, stdin);

		processCommand(sockfd, line);
	}

	close(sockfd);

	return 0;
}

void * receive(void * cs) {
	int clientSocket = *((int*)cs);
	char line[BUFFER_SIZE];
	int i;
	while (1) {
		if (recv(clientSocket, line, BUFFER_SIZE, 0) == 0) {
			printf("You were kicked from the chat.\n");
			exit(0);
		}

		switch (line[0]) {
			case OP_BROADCAST:
				printf("%s (to everyone): %s", line + 1, line + 257);
				break;
			case OP_CLIENT_LIST:
				printf("Clients in this chat:\n");
				for (i = 0; i <= 5; i++) {
					if (strlen(line + 1 + (i * 256)) == 0) {
						break;
					}
					printf("\t%s\n", line + 1 + (i * 256));
				}
				break;
		}
		
		//printf("Got message from server: %s", line);
	}
}

void processCommand(int sockfd, char * message) {
	char * token;
	int i = 0;
	int sizeOfCommand;
	int sizeOfUsername;
	char * command;
	char * user;
	char * content;
	char outgoing[513];

	if (message[0] != '/') {
		outgoing[0] = OP_BROADCAST;
		strcpy(outgoing + 1, message);
		send(sockfd, outgoing, strlen(outgoing) + 1, 0);
		return;
	}
	
	while ((token = strsep(&message, " ")) != NULL) {
		if (i == 0) {
			printf("Set command to %s\n", token);
			command = malloc(strlen(token) + 1);
			strcpy(command, token);
			sizeOfCommand = strlen(token) + 1;
			i++;
			continue;
		}

		if (i == 1) {
			printf("Set user to %s\n", token);
			user = malloc(strlen(token) + 1);
			strcpy(user, token);
			sizeOfUsername = strlen(token) + 1;
			i++;
			continue;
		}
		
		if (i == 2) {
			content = malloc(256 - (sizeOfCommand + sizeOfUsername));
			strcpy(content, message + sizeOfCommand + sizeOfUsername);
			printf("Set content to %s\n", content);
			i++;
			continue;
		}

		i++;
	}

	if (strcmp(command, "/end") == 0) {
		//TODO
		return;
	}

	if (strcmp(command, "/whisper") == 0) {
		printf("Got a whisper command.\n");
		outgoing[0] = OP_WHISPER;
		strcpy(outgoing + 1, user);
		strcpy(outgoing + 1 + 256, content);
		send(sockfd, outgoing, strlen(outgoing) + 1, 0);
		return;
	}

	if (strcmp(command, "/kick") == 0) {
		outgoing[0] = OP_KICK_USER;
		strcpy(outgoing + 1, user);
		send(sockfd, outgoing, strlen(outgoing) + 1, 0);
		return;
	}

	if (strcmp(command, "/help") == 0) {

		return;
	}

	if (strcmp(command, "/list\n") == 0) {
		outgoing[0] = OP_CLIENT_LIST;
		send(sockfd, outgoing, strlen(outgoing) + 1, 0);
		return;
	}

	printf("Command not found. Type /help for help.\n");
}







