/*
 * CIS 457
 * Project 4
 * Server
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

struct User {
	int valid;
	char name[256];
	int sockfd;
};

struct User users[100];
pthread_mutex_t lock;

void * server(void * clientSocket);
void getUsername(char * username, int sockfd);

int main(int argc, char **argv) {
	if (pthread_mutex_init(&lock, NULL) != 0) {
		printf("Mutex init failed. Exiting.\n");
		return 1;
	}

	int i;
	for (i = 0; i < 100; i++) {
		users[i].valid = 0;
	}

	int sockfd, newsockfd, *newSock;

	if (argc != 2) {
		printf("Wrong number of arguments; make sure you specify a port number.\n");
		return 1;
	}

	int port = atoi(argv[1]);
	
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	
	struct sockaddr_in serveraddr, clientaddr;
	serveraddr.sin_family      = AF_INET;
	serveraddr.sin_port        = htons(port);
	serveraddr.sin_addr.s_addr = INADDR_ANY;

	bind(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr));
	listen(sockfd, 10);

	int len = sizeof(clientaddr);

	while (1) {
		newsockfd = accept(sockfd, (struct sockaddr*)&clientaddr, &len);

		newSock = malloc(1);
		*newSock = newsockfd;

		if (newsockfd < 0) {
			perror("Error on accept.");
			exit(1);
		}

		pthread_t pid;
		if (pthread_create(&pid, NULL, server, (void *) newSock)) {
			fprintf(stderr, "Error creating thread...\n");
			return 1;
		}
	}

	pthread_mutex_destroy(&lock);
}


void * server(void * cs) {
	//This is the sockfd
	int clientSocket = *((int *)cs);

	while(1) {
		char line[BUFFER_SIZE];
		recv(clientSocket, line, BUFFER_SIZE, 0);
		
		int success = 0;
		char username[256];
		switch (line[0]) {
			case OP_INIT:
				success = addUser(line + 1, clientSocket);
				if (!success) {
					//TODO: Send error to user.
				}
				break;
			case OP_BROADCAST:
				getUsername(username, clientSocket);
				printf("Sending a broadcast message from user %s.\n", username);
				broadcast(username, line + 1);
				break;
		}
	}

	close(clientSocket);
}

//Returns 1 if successful, 0 otherwise
int addUser(char name[256], int sockfd) {
	pthread_mutex_lock(&lock);
	int i;

	for (i = 0; i < 100; i++) {
		if (users[i].valid == 1 && strcmp(name, users[i].name) == 0) {
			printf("This username is already taken.\n");
			pthread_mutex_unlock(&lock);
			return 0;
		} else {
			//TODO: Broadcast this.
			printf("User %s has joined the chat.\n", name);
			users[i].valid = 1;
			memcpy(users[i].name, name, 256);
			users[i].sockfd = sockfd;
			pthread_mutex_unlock(&lock);
			return 1;
		}
	}

	//Chat is full
	pthread_mutex_unlock(&lock);
	return 0;
}

int broadcast(char sender[256], char message[MESSAGE_SIZE]) {
	int i;
	char outgoing[514];
	strcpy(outgoing, sender);
	outgoing[257] = ':';
	outgoing[258] = ' ';
	strcpy(outgoing + 258, message);

	for (i = 0; i < 100; i++) {
		if (strcmp(sender, users[i].name) != 0 && users[i].valid == 1) {
			printf("Sending broadcast message to %s on sfd %d.\n", users[i].name, users[i].sockfd);
			send(users[i].sockfd, outgoing, 514, 0);
		}
	}
}

void getUsername(char * username, int sockfd) {
	int i;	
	for (i = 0; i < 100; i++) {
		if (users[i].sockfd == sockfd) {
			printf("Found a user. User name: %s.\n", users[i].name);
			strcpy(username, users[i].name);
			break;
		}
	}
}







