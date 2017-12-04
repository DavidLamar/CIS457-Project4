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

#include <errno.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>

#define MAX_THREAD_NUMBER 100
#define W_READ  1
#define W_WRITE 2
#define C_DONE  1
#define S_DONE  2

#define BUFFER_SIZE 1500
#define MESSAGE_SIZE 256
#define OP_INIT        0x00
#define OP_SYM	       0x01
#define OP_BROADCAST   0x02
#define OP_WHISPER     0x03
#define OP_CLIENT_LIST 0x04
#define OP_KICK_USER   0x05

BIO *bio_err = NULL;
BIO *bio_stdout = NULL;
int thread_number = 10;
int number_of_loops = 10;
int reconnect = 0;
int verbose = 0;

struct User {
	int valid;
	char name[256];
	int sockfd;
	pthread_t pid;
	unsigned char dKey[32];
	unsigned char dIv[16];
};

struct User users[100];
pthread_mutex_t lock;


char * publicKey;
long publicKeySize;
EVP_PKEY *privkey;
unsigned char key[32];
unsigned char iv[16];

void * server(void * clientSocket);
void getUsername(char * username, int sockfd);
void whisper(char username[256], char * message, int fromSocket);
void removeUser(char name[256]);
void kickUser(char username[256]);
struct User getUser(char username[256]);
struct User getUserBySockfd(int sockfd);
void clientList(int sockfd);


void thread_setup(void);
void thread_cleanup(void);
void do_threads(SSL_CTX *s_ctx, SSL_CTX *c_ctx);
void pthreads_thread_id(CRYPTO_THREADID *tid);
void pthreads_locking_callback(int mode, int type, const char *file, int line);
int doit(char *ctx[4]);

int main(int argc, char **argv) {
	thread_setup();

	//RSA setup:
	unsigned char *pubfilename = "RSApub.pem";
	unsigned char *privfilename = "RSApriv.pem";
	unsigned char *plaintext = (unsigned char *) "This is a test string to encrypt.";
	unsigned char ciphertext[1024];
	unsigned char decryptedtext[1024];
	int decryptedtext_len, ciphertext_len;
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
	RAND_bytes(key, 32);
	RAND_pseudo_bytes(iv, 16);

	FILE* pubf = fopen(pubfilename, "rb");
	FILE* privf = fopen(privfilename,"rb");

  	privkey = PEM_read_PrivateKey(privf, NULL, NULL, NULL);

	fseek(pubf, 0L, SEEK_END);
	publicKeySize = ftell(pubf);
	rewind(pubf);
	publicKey = calloc(1, publicKeySize + 1);
	fread(publicKey, publicKeySize, 1, pubf);

	fclose(pubf);
	//End RSA setup


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
	int i;

	while(1) {
		char encryptedMessage[BUFFER_SIZE];
		char line[BUFFER_SIZE];
		recv(clientSocket, encryptedMessage, BUFFER_SIZE, 0);
		
		if (encryptedMessage[0] != OP_INIT && encryptedMessage[0] != OP_SYM) {
			int encryptedMessageLen = encryptedMessage[1] << 24 | encryptedMessage[2] << 16 | encryptedMessage[3] << 8 | encryptedMessage[4];
			printf("About to decrypt with size %d.\n", encryptedMessageLen);

			struct User currentUser = getUserBySockfd(clientSocket);
			decrypt(encryptedMessage + 5, encryptedMessageLen, currentUser.dKey, currentUser.dIv, line + 1);
		}
		
		int success = 0;
		int cipherLen;
		char username[256];
		for (i = 0; i < 256; i++) {
			username[i] = '\0';
		}
		char keyMessage[513 + 16];
		switch (encryptedMessage[0]) {
			case OP_INIT:
				printf("Got init message.\n");
				keyMessage[0] = OP_INIT;
				memcpy(keyMessage + 1, iv, 16);
				strcpy(keyMessage + 1 + 16, publicKey);
				send(clientSocket, keyMessage, 513 + 16, 0);
				break;
			case OP_SYM:
				cipherLen = encryptedMessage[1] << 24 | encryptedMessage[2] << 16 | encryptedMessage[3] << 8 | encryptedMessage[4];
				
				unsigned char decryptedMessage[32 + 16];
				unsigned char dKey[32];
				unsigned char dIv[16];

  				rsa_decrypt(encryptedMessage + 5 + 16, cipherLen, privkey, decryptedMessage);

				memcpy(dKey, decryptedMessage, 32);
				memcpy(dIv, encryptedMessage + 5, 16);

				int messageLen = encryptedMessage[514] << 24 | encryptedMessage[515] << 16 | encryptedMessage[516] << 8 | encryptedMessage[517];
				
				decrypt(encryptedMessage + 518, messageLen, dKey, dIv, username);

				username[messageLen] = '\0';

				success = addUser(username, clientSocket, dKey, dIv);
				break;
			case OP_BROADCAST:
				getUsername(username, clientSocket);
				printf("Sending a broadcast message from user %s.\n", username);
				broadcast(username, line + 1);
				break;
			case OP_WHISPER:
				printf("Got a whisper command.\n");
				whisper(line + 1, line + 257, clientSocket);
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
int addUser(char name[256], int sockfd, unsigned char dKey[32], unsigned char dIv[16]) {
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
			memcpy(users[i].dKey, dKey, 32);
			memcpy(users[i].dIv, dIv, 16);
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
	char outgoing[1029];
	char messageToEncrypt[512];
	strcpy(messageToEncrypt, sender);
	strcpy(messageToEncrypt + 256, message);

	outgoing[0] = OP_BROADCAST;

	for (i = 0; i < 100; i++) {
		if (strcmp(sender, users[i].name) != 0 && users[i].valid == 1) {
			printf("Sending broadcast message to %s on sfd %d.\n", users[i].name, users[i].sockfd);

			int encryptedLen = encrypt(messageToEncrypt, 513, users[i].dKey, users[i].dIv, outgoing + 5);

			printf("Encrypted message length is %d.\n", encryptedLen);
			outgoing[1] = (encryptedLen >> 24) & 0xFF;
			outgoing[2] = (encryptedLen >> 16) & 0xFF;
			outgoing[3] = (encryptedLen >> 8) & 0xFF;
			outgoing[4] = encryptedLen & 0xFF;
			send(users[i].sockfd, outgoing, 1029, 0);
		}
	}
}


void whisper(char username[256], char * message, int fromSocket) {
	printf("Sending a whisper from %d to %s with message %s.\n", fromSocket, username, message);
	struct User user = getUser(username);
	char outgoing[1029];
	char messageToEncrypt[512];

	struct User sender = getUserBySockfd(fromSocket);

	strcpy(messageToEncrypt, sender.name);
	strcpy(messageToEncrypt + 256, message);
	
	if (user.valid != 1 || sender.valid != 1) {
		printf("No such user.\n");
		//TODO: Send error to user.
		return;
	}

	printf("Sending a whisper from %s to %s.\n", sender.name, username);

	outgoing[0] = OP_WHISPER;

	int encryptedLen = encrypt(messageToEncrypt, 513, user.dKey, user.dIv, outgoing + 5);

	printf("Encrypted message length is %d.\n", encryptedLen);
	outgoing[1] = (encryptedLen >> 24) & 0xFF;
	outgoing[2] = (encryptedLen >> 16) & 0xFF;
	outgoing[3] = (encryptedLen >> 8) & 0xFF;
	outgoing[4] = encryptedLen & 0xFF;

	send(user.sockfd, outgoing, 1029, 0);
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
			strcpy(message + (userNum * 256) + 5, users[i].name);
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









//****** Kalafut's Code **************//

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int rsa_encrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out){ 
  EVP_PKEY_CTX *ctx;
  size_t outlen;
  ctx = EVP_PKEY_CTX_new(key, NULL);
  if (!ctx)
    handleErrors();
  if (EVP_PKEY_encrypt_init(ctx) <= 0)
    handleErrors();
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    handleErrors();
  if (EVP_PKEY_encrypt(ctx, NULL, &outlen, in, inlen) <= 0)
    handleErrors();
  if (EVP_PKEY_encrypt(ctx, out, &outlen, in, inlen) <= 0)
    handleErrors();
  return outlen;
}

int rsa_decrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out){ 
  EVP_PKEY_CTX *ctx;
  size_t outlen;
  ctx = EVP_PKEY_CTX_new(key,NULL);
  if (!ctx)
    handleErrors();
  if (EVP_PKEY_decrypt_init(ctx) <= 0)
    handleErrors();
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    handleErrors();
  if (EVP_PKEY_decrypt(ctx, NULL, &outlen, in, inlen) <= 0)
    handleErrors();
  if (EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen) <= 0)
    handleErrors();
  return outlen;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext){
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	    unsigned char *iv, unsigned char *plaintext){
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}


//****** End Kalafut's Code **************//





//****** OpenSSL Code **************//

static pthread_mutex_t *lock_cs;
static long *lock_count;

int doit(char *ctx[4])
{
    SSL_CTX *s_ctx, *c_ctx;
    static char cbuf[200], sbuf[200];
    SSL *c_ssl = NULL;
    SSL *s_ssl = NULL;
    BIO *c_to_s = NULL;
    BIO *s_to_c = NULL;
    BIO *c_bio = NULL;
    BIO *s_bio = NULL;
    int c_r, c_w, s_r, s_w;
    int c_want, s_want;
    int i;
    int done = 0;
    int c_write, s_write;
    int do_server = 0, do_client = 0;

    s_ctx = (SSL_CTX *)ctx[0];
    c_ctx = (SSL_CTX *)ctx[1];

    if (ctx[2] != NULL)
        s_ssl = (SSL *)ctx[2];
    else
        s_ssl = SSL_new(s_ctx);

    if (ctx[3] != NULL)
        c_ssl = (SSL *)ctx[3];
    else
        c_ssl = SSL_new(c_ctx);

    if ((s_ssl == NULL) || (c_ssl == NULL))
        goto err;

    c_to_s = BIO_new(BIO_s_mem());
    s_to_c = BIO_new(BIO_s_mem());
    if ((s_to_c == NULL) || (c_to_s == NULL))
        goto err;

    c_bio = BIO_new(BIO_f_ssl());
    s_bio = BIO_new(BIO_f_ssl());
    if ((c_bio == NULL) || (s_bio == NULL))
        goto err;

    SSL_set_connect_state(c_ssl);
    SSL_set_bio(c_ssl, s_to_c, c_to_s);
    BIO_set_ssl(c_bio, c_ssl, (ctx[2] == NULL) ? BIO_CLOSE : BIO_NOCLOSE);

    SSL_set_accept_state(s_ssl);
    SSL_set_bio(s_ssl, c_to_s, s_to_c);
    BIO_set_ssl(s_bio, s_ssl, (ctx[3] == NULL) ? BIO_CLOSE : BIO_NOCLOSE);

    c_r = 0;
    s_r = 1;
    c_w = 1;
    s_w = 0;
    c_want = W_WRITE;
    s_want = 0;
    c_write = 1, s_write = 0;

    /* We can always do writes */
    for (;;) {
        do_server = 0;
        do_client = 0;

        i = (int)BIO_pending(s_bio);
        if ((i && s_r) || s_w)
            do_server = 1;

        i = (int)BIO_pending(c_bio);
        if ((i && c_r) || c_w)
            do_client = 1;

        if (do_server && verbose) {
            if (SSL_in_init(s_ssl))
                BIO_printf(bio_stdout, "server waiting in SSL_accept - %s\n",
                           SSL_state_string_long(s_ssl));
            else if (s_write)
                BIO_printf(bio_stdout, "server:SSL_write()\n");
            else
                BIO_printf(bio_stdout, "server:SSL_read()\n");
        }

        if (do_client && verbose) {
            if (SSL_in_init(c_ssl))
                BIO_printf(bio_stdout, "client waiting in SSL_connect - %s\n",
                           SSL_state_string_long(c_ssl));
            else if (c_write)
                BIO_printf(bio_stdout, "client:SSL_write()\n");
            else
                BIO_printf(bio_stdout, "client:SSL_read()\n");
        }

        if (!do_client && !do_server) {
            BIO_printf(bio_stdout, "ERROR IN STARTUP\n");
            break;
        }
        if (do_client && !(done & C_DONE)) {
            if (c_write) {
                i = BIO_write(c_bio, "hello from client\n", 18);
                if (i < 0) {
                    c_r = 0;
                    c_w = 0;
                    if (BIO_should_retry(c_bio)) {
                        if (BIO_should_read(c_bio))
                            c_r = 1;
                        if (BIO_should_write(c_bio))
                            c_w = 1;
                    } else {
                        BIO_printf(bio_err, "ERROR in CLIENT\n");
                        ERR_print_errors_fp(stderr);
                        return (1);
                    }
                } else if (i == 0) {
                    BIO_printf(bio_err, "SSL CLIENT STARTUP FAILED\n");
                    return (1);
                } else {
                    /* ok */
                    c_write = 0;
                }
            } else {
                i = BIO_read(c_bio, cbuf, 100);
                if (i < 0) {
                    c_r = 0;
                    c_w = 0;
                    if (BIO_should_retry(c_bio)) {
                        if (BIO_should_read(c_bio))
                            c_r = 1;
                        if (BIO_should_write(c_bio))
                            c_w = 1;
                    } else {
                        BIO_printf(bio_err, "ERROR in CLIENT\n");
                        ERR_print_errors_fp(stderr);
                        return (1);
                    }
                } else if (i == 0) {
                    BIO_printf(bio_err, "SSL CLIENT STARTUP FAILED\n");
                    return (1);
                } else {
                    done |= C_DONE;
#ifdef undef
                    BIO_printf(bio_stdout, "CLIENT:from server:");
                    BIO_write(bio_stdout, cbuf, i);
                    BIO_flush(bio_stdout);
#endif
                }
            }
        }

        if (do_server && !(done & S_DONE)) {
            if (!s_write) {
                i = BIO_read(s_bio, sbuf, 100);
                if (i < 0) {
                    s_r = 0;
                    s_w = 0;
                    if (BIO_should_retry(s_bio)) {
                        if (BIO_should_read(s_bio))
                            s_r = 1;
                        if (BIO_should_write(s_bio))
                            s_w = 1;
                    } else {
                        BIO_printf(bio_err, "ERROR in SERVER\n");
                        ERR_print_errors_fp(stderr);
                        return (1);
                    }
                } else if (i == 0) {
                    BIO_printf(bio_err, "SSL SERVER STARTUP FAILED\n");
                    return (1);
                } else {
                    s_write = 1;
                    s_w = 1;
#ifdef undef
                    BIO_printf(bio_stdout, "SERVER:from client:");
                    BIO_write(bio_stdout, sbuf, i);
                    BIO_flush(bio_stdout);
#endif
                }
            } else {
                i = BIO_write(s_bio, "hello from server\n", 18);
                if (i < 0) {
                    s_r = 0;
                    s_w = 0;
                    if (BIO_should_retry(s_bio)) {
                        if (BIO_should_read(s_bio))
                            s_r = 1;
                        if (BIO_should_write(s_bio))
                            s_w = 1;
                    } else {
                        BIO_printf(bio_err, "ERROR in SERVER\n");
                        ERR_print_errors_fp(stderr);
                        return (1);
                    }
                } else if (i == 0) {
                    BIO_printf(bio_err, "SSL SERVER STARTUP FAILED\n");
                    return (1);
                } else {
                    s_write = 0;
                    s_r = 1;
                    done |= S_DONE;
                }
            }
        }

        if ((done & S_DONE) && (done & C_DONE))
            break;
#if defined(OPENSSL_SYS_NETWARE)
        ThreadSwitchWithDelay();
#endif
    }

    SSL_set_shutdown(c_ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    SSL_set_shutdown(s_ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);

#ifdef undef
    BIO_printf(bio_stdout, "DONE\n");
#endif
 err:
    /*
     * We have to set the BIO's to NULL otherwise they will be free()ed
     * twice.  Once when th s_ssl is SSL_free()ed and again when c_ssl is
     * SSL_free()ed. This is a hack required because s_ssl and c_ssl are
     * sharing the same BIO structure and SSL_set_bio() and SSL_free()
     * automatically BIO_free non NULL entries. You should not normally do
     * this or be required to do this
     */

    if (s_ssl != NULL) {
        s_ssl->rbio = NULL;
        s_ssl->wbio = NULL;
    }
    if (c_ssl != NULL) {
        c_ssl->rbio = NULL;
        c_ssl->wbio = NULL;
    }

    /* The SSL's are optionally freed in the following calls */
    if (c_to_s != NULL)
        BIO_free(c_to_s);
    if (s_to_c != NULL)
        BIO_free(s_to_c);

    if (c_bio != NULL)
        BIO_free(c_bio);
    if (s_bio != NULL)
        BIO_free(s_bio);
    return (0);
}

int ndoit(SSL_CTX *ssl_ctx[2])
{
    int i;
    int ret;
    char *ctx[4];
    CRYPTO_THREADID thread_id;

    ctx[0] = (char *)ssl_ctx[0];
    ctx[1] = (char *)ssl_ctx[1];

    if (reconnect) {
        ctx[2] = (char *)SSL_new(ssl_ctx[0]);
        ctx[3] = (char *)SSL_new(ssl_ctx[1]);
    } else {
        ctx[2] = NULL;
        ctx[3] = NULL;
    }

    CRYPTO_THREADID_current(&thread_id);
    BIO_printf(bio_stdout, "started thread %lu\n",
	       CRYPTO_THREADID_hash(&thread_id));
    for (i = 0; i < number_of_loops; i++) {
/*-     BIO_printf(bio_err,"%4d %2d ctx->ref (%3d,%3d)\n",
                   CRYPTO_THREADID_hash(&thread_id),i,
                   ssl_ctx[0]->references,
                   ssl_ctx[1]->references); */
/*      pthread_delay_np(&tm); */

        ret = doit(ctx);
        if (ret != 0) {
            BIO_printf(bio_stdout, "error[%d] %lu - %d\n",
                       i, CRYPTO_THREADID_hash(&thread_id), ret);
            return (ret);
        }
    }
    BIO_printf(bio_stdout, "DONE %lu\n", CRYPTO_THREADID_hash(&thread_id));
    if (reconnect) {
        SSL_free((SSL *)ctx[2]);
        SSL_free((SSL *)ctx[3]);
    }
#ifdef OPENSSL_SYS_NETWARE
    MPKSemaphoreSignal(ThreadSem);
#endif
    return (0);
}

void thread_setup(void)
{
    int i;

    lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        lock_count[i] = 0;
        pthread_mutex_init(&(lock_cs[i]), NULL);
    }

    CRYPTO_THREADID_set_callback(pthreads_thread_id);
    CRYPTO_set_locking_callback(pthreads_locking_callback);
}

void thread_cleanup(void)
{
    int i;

    CRYPTO_set_locking_callback(NULL);
    BIO_printf(bio_err, "cleanup\n");
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_destroy(&(lock_cs[i]));
        BIO_printf(bio_err, "%8ld:%s\n", lock_count[i], CRYPTO_get_lock_name(i));
    }
    OPENSSL_free(lock_cs);
    OPENSSL_free(lock_count);

    BIO_printf(bio_err, "done cleanup\n");
}

void pthreads_locking_callback(int mode, int type, const char *file, int line)
{
# ifdef undef
    BIO_printf(bio_err, "thread=%4d mode=%s lock=%s %s:%d\n",
               CRYPTO_thread_id(),
               (mode & CRYPTO_LOCK) ? "l" : "u",
               (type & CRYPTO_READ) ? "r" : "w", file, line);
# endif
/*-
    if (CRYPTO_LOCK_SSL_CERT == type)
            BIO_printf(bio_err,"(t,m,f,l) %ld %d %s %d\n",
                       CRYPTO_thread_id(),
                       mode,file,line);
*/
    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&(lock_cs[type]));
        lock_count[type]++;
    } else {
        pthread_mutex_unlock(&(lock_cs[type]));
    }
}

void do_threads(SSL_CTX *s_ctx, SSL_CTX *c_ctx)
{
    SSL_CTX *ssl_ctx[2];
    pthread_t thread_ctx[MAX_THREAD_NUMBER];
    int i;

    ssl_ctx[0] = s_ctx;
    ssl_ctx[1] = c_ctx;

    /*
     * thr_setconcurrency(thread_number);
     */
    for (i = 0; i < thread_number; i++) {
        pthread_create(&(thread_ctx[i]), NULL,
                       (void *(*)())ndoit, (void *)ssl_ctx);
    }

    BIO_printf(bio_stdout, "reaping\n");
    for (i = 0; i < thread_number; i++) {
        pthread_join(thread_ctx[i], NULL);
    }

#if 0 /* We can't currently find out the reference amount */
    BIO_printf(bio_stdout, "pthreads threads done (%d,%d)\n",
               s_ctx->references, c_ctx->references);
#else
    BIO_printf(bio_stdout, "pthreads threads done\n");
#endif
}

void pthreads_thread_id(CRYPTO_THREADID *tid)
{//****** OpenSSL Code **************//
    CRYPTO_THREADID_set_numeric(tid, (unsigned long)pthread_self());
}

//****** End OpenSSL Code **************//

