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
#define OP_WHISPER 0x02
#define OP_CLIENT_LIST 0x03
#define OP_KICK_USER 0x04

struct User {
	int valid;
	char name[256];
	int sockfd;
	pthread_t pid;
};

struct User users[100];
pthread_mutex_t lock;

void * server(void * clientSocket);
void getUsername(char * username, int sockfd);
void whisper(char username[256], char message[256]);
void removeUser(char name[256]);
void kickUser(char username[256]);
struct User getUser(char username[256]);
struct User getUserBySockfd(int sockfd);
void clientList(int sockfd);

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
			case OP_WHISPER:
				whisper(line + 1, line + 257);
				break;
			case OP_CLIENT_LIST:
				printf("Got client list command.\n");
				clientList(clientSocket);
				break;
			case OP_KICK_USER:
				printf("Got a kick command.\n");
				kickUser(line + 1);
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
		if (users[i].valid == 1) {
			if (strcmp(name, users[i].name) == 0) {
				printf("Username is taken.\n");
				pthread_mutex_unlock(&lock);
				return 0;
			}
			continue;
		} else {
			printf("Setting user %d to %s.\n", i, name);
			//TODO: Broadcast this.
			printf("User %s has joined the chat.\n", name);
			users[i].valid = 1;
			memcpy(users[i].name, name, 256);
			users[i].sockfd = sockfd;
			users[i].pid = pthread_self();
			pthread_mutex_unlock(&lock);
			return 1;
		}
	}

	//Chat is full
	pthread_mutex_unlock(&lock);
	return 0;
}

void removeUser(char name[256]) {
	pthread_mutex_lock(&lock);

	int i;
	for (i = 0; i < 100; i++) {
		if (strcmp(name, users[i].name) == 0) {
			users[i].valid = 0;
			break;
		}
	}

	pthread_mutex_unlock(&lock);
}

int broadcast(char sender[256], char message[MESSAGE_SIZE]) {
	int i;
	char outgoing[513];
	outgoing[0] = OP_BROADCAST;
	strcpy(outgoing + 1, sender);
	strcpy(outgoing + 1 + 256, message);

	for (i = 0; i < 100; i++) {
		//printf("For user %s:\n\tValid bit is %d\n\tSockfd is %d\n\n", users[i].name, users[i].valid, users[i].sockfd);
		if (strcmp(sender, users[i].name) != 0 && users[i].valid == 1) {
			printf("Sending broadcast message to %s on sfd %d.\n", users[i].name, users[i].sockfd);
			send(users[i].sockfd, outgoing, 513, 0);
		}
	}
}


void whisper(char username[256], char message[256]) {
	int sockfd = getSockfd(username);
	
	if (sockfd == -1) {
		printf("No such user.\n");
		//TODO: Send error to user.
		return;
	}

	send(sockfd, message, 256, 0);
}

void kickUser(char username[256]) {
	username[strlen(username) - 1] = 0;
	struct User user = getUser(username);
	
	if (user.valid == 0) {
		printf("No such user.\n");
		//TODO: Send error to user.
		return;
	}

	removeUser(username);
	close(user.sockfd);
	pthread_cancel(user.pid);
	printf("%s was kicked from the chat.\n", username);
}

void clientList(int sockfd) {
	char message[1500];
	int i;	
	for (i = 0; i < 1500; i++) {
		message[i] = 0;
	}
	struct User user = getUserBySockfd(sockfd);

	message[0] = OP_CLIENT_LIST;

	int userNum = 0;
	for (i = 0; i < 100; i++) {
		if (users[i].valid && strcmp(user.name, users[i].name) != 0) {
			strcpy(message + (userNum * 256) + 1, users[i].name);
			userNum++;
		}
	}

	send(user.sockfd, message, 1500, 0);
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

int getSockfd(char username[256]) {
	int i;
	for (i = 0; i < 100; i++) {
		printf("Comparing %s to %s\n", username, users[i].name);
		if (users[i].valid && strcmp(username, users[i].name) == 0) {
			return users[i].sockfd;
		}
	}

	return -1;
}

struct User getUser(char username[256]) {
	struct User NULL_USER = {.valid = 0};
	int i;
	for (i = 0; i < 100; i++) {
		if (users[i].valid && strcmp(username, users[i].name) == 0) {
			return users[i];
		}
	}

	return NULL_USER;
}

struct User getUserBySockfd(int sockfd) {
	struct User NULL_USER = {.valid = 0};
	int i;
	for (i = 0; i < 100; i++) {
		if (users[i].valid && users[i].sockfd == sockfd) {
			return users[i];
		}
	}

	return NULL_USER;
}









