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


EVP_PKEY *serverPublicKey;
unsigned char serverIv[16];

char * userName;

unsigned char key[32];
unsigned char iv[16];


void * receive(void * cs);
void processCommand(int sockfd, char * message);

void thread_setup(void);
void thread_cleanup(void);
void do_threads(SSL_CTX *s_ctx, SSL_CTX *c_ctx);
void pthreads_thread_id(CRYPTO_THREADID *tid);
void pthreads_locking_callback(int mode, int type, const char *file, int line);
int doit(char *ctx[4]);



int main(int argc, char **argv) {
	thread_setup();
	if (argc != 4) {
		printf("Wrong number of arguments; make sure you specify the following:\n");
		printf("\tIP Address\n");
		printf("\tPort Number\n");
		printf("\tUser name\n");
		return 1;
	}

	char * ipAddress = argv[1];
	int port = atoi(argv[2]);
	userName = argv[3];

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

	bind(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr));

	//Request init information:
	char init[1] = {OP_INIT};
	send(sockfd, init, 1, 0);

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
	char encryptedText[BUFFER_SIZE];
	char line[BUFFER_SIZE];
	int i;
	while (1) {
		if (recv(clientSocket, encryptedText, BUFFER_SIZE, 0) == 0) {
			printf("You were kicked from the chat.\n");
			exit(0);
		}

		unsigned char encryptedKey[256];
		int symSize = 32;
		unsigned char symMessage[symSize];
		unsigned char message[513 + 256 + 4];
		BIO * bio;

		if (encryptedText[0] != OP_INIT && encryptedText[0] != OP_SYM) {
			int encryptedMessageLen = encryptedText[1] << 24 | encryptedText[2] << 16 | encryptedText[3] << 8 | encryptedText[4];
			decrypt(encryptedText + 5, encryptedMessageLen, key, iv, line + 1);
			line[encryptedMessageLen] = '\0'; 
		}


		switch (encryptedText[0]) {
			case OP_INIT:
				bio = BIO_new_mem_buf(encryptedText + 1 + 16, strlen(encryptedText + 1 + 16) + 1);
				serverPublicKey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);

				memcpy(serverIv, encryptedText + 1, 16);

				RAND_bytes(key, 32);
  				RAND_pseudo_bytes(iv, 16);
				
				memcpy(symMessage, key, 32);
				
				int encryptedKeyLen = rsa_encrypt(key, 32, serverPublicKey, encryptedKey);
				
				message[0] = OP_SYM;
				message[1] = (encryptedKeyLen >> 24) & 0xFF;
				message[2] = (encryptedKeyLen >> 16) & 0xFF;
				message[3] = (encryptedKeyLen >> 8) & 0xFF;
				message[4] = encryptedKeyLen & 0xFF;

				memcpy(message + 5, iv, 16);
				memcpy(message + 5 + 16, encryptedKey, encryptedKeyLen);

				printf("Username is: %s.\n", userName);

				int nameLen = encrypt(userName, strlen(userName) + 1, key, iv, message + 518);
				message[514] = (nameLen >> 24) & 0xFF;
				message[515] = (nameLen >> 16) & 0xFF;
				message[516] = (nameLen >> 8) & 0xFF;
				message[517] = nameLen & 0xFF;

				send(clientSocket, message, 513 + 256 + 4, 0);
				break;
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
			case OP_WHISPER:
				printf("%s (to you): %s", line + 1, line + 257);
				break;
		}
	}
}

void processCommand(int sockfd, char * message) {
	char * token;
	int i = 0;
	int sizeOfCommand;
	int sizeOfUsername;
	int sizeOfContent;
	char * messageCopy;
	char * command;
	char * user;
	char * content;
	char outgoing[1029];
	char messageContent[512];
	int validCommand = 0;

	messageCopy = malloc(strlen(message) + 1);
	strcpy(messageCopy, message);

	if (message[0] != '/') {
		validCommand = 1;
		outgoing[0] = OP_BROADCAST;
		strcpy(messageContent, message);
		messageContent[strlen(message) + 1] = '\0';
	} else {
		//Have a command
		while ((token = strsep(&messageCopy, " ")) != NULL) {
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
				user[sizeOfUsername] = '\0';
				i++;
				continue;
			}
		
			if (i == 2) {
				content = malloc(256 - (sizeOfCommand + sizeOfUsername));
				strcpy(content, message + sizeOfCommand + sizeOfUsername);
				sizeOfContent = 256 - (sizeOfCommand + sizeOfUsername);
				content[sizeOfContent] = '\0';
				printf("Set content to %s\n", content);
				i++;
				continue;
			}

			i++;
		}

		if (strcmp(command, "/end") == 0) {
			//TODO
		}

		if (strcmp(command, "/whisper") == 0) {
			validCommand = 1;
			outgoing[0] = OP_WHISPER;
			strcpy(messageContent, user);
			messageContent[sizeOfUsername] = '\0';
			strcpy(messageContent + 256, content);
			messageContent[256 + sizeOfContent] = '\0';
		}

		if (strcmp(command, "/kick") == 0) {
			validCommand = 1;
			outgoing[0] = OP_KICK_USER;
			strcpy(messageContent, user);
		}

		if (strcmp(command, "/help") == 0) {

		}

		if (strcmp(command, "/list\n") == 0) {
			validCommand = 1;
			outgoing[0] = OP_CLIENT_LIST;
		}
	}
	
	

	if (validCommand) {
		unsigned char cipherText[1024];
		int cipherTextLen;
		
		cipherTextLen = encrypt(messageContent, 512, key, iv, cipherText);
		
		outgoing[1] = (cipherTextLen >> 24) & 0xFF;
		outgoing[2] = (cipherTextLen >> 16) & 0xFF;
		outgoing[3] = (cipherTextLen >> 8) & 0xFF;
		outgoing[4] = cipherTextLen & 0xFF;
		memcpy(outgoing + 5, cipherText, 1024);
		printf("Encrypted message length: %d\n", cipherTextLen);

		//TODO: Check server to make sure we're not cutting off last 4 bytes
		send(sockfd, outgoing, 1029, 0);
		return;
	}

	printf("Command not found. Type /help for help.\n");
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
