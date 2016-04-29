/* serv.cpp  -  Minimal ssleay server for Unix
   30.9.1996, Sampo Kellomaki <sampo@iki.fi> */


/* mangled to work with SSLeay-0.9.0b and OpenSSL 0.9.2b
   Simplified to be even more minimal
   12/98 - 4/99 Wade Scholine <wades@mail.cybg.com> */
   
/* CIS 644 Internet Security final project - MiniVPN
 * integrated with tunproxy to setup data transmission UDP tunnel with encryption/HMAC
 * Using IPC to manipulate SSL TCP tunnel & UDP tunnel
 * 2016/4/29, Lingwei Wu <lwu108@syr.edu>, Syracuse University
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <getopt.h>
#include <sys/ioctl.h>

#include <openssl/rsa.h>       /* SSLeay stuff */
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "openssl/sha.h"

/* define HOME to be dir for key and cert files... */
#define HOME "./"
/* Make these what you want for cert & key files */
#define CERTF  HOME "server.crt"
#define KEYF  HOME  "server.key"
#define CACERT HOME "ca.crt"

#define HASHLEN 32
#define SALTLEN 5

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

int sha256(char *input, unsigned char *output)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);  
    if(!SHA256_Update(&ctx, input, strlen(input))) return 0;
    if(!SHA256_Final(hash, &ctx)) return 0;
    
    printf("SHA256,strlen(hash):%d\n",strlen(hash));
    strncpy(output,hash,HASHLEN);
    printf("SHA256,strlen(output):%d\n",strlen(output));
    
    
    int i = 0;
    for(i = 0;i < HASHLEN ; i++) {
    	printf("%02x",output[i]);
    }
    printf("\n");
    return 1;

}


int main ()
{
  int err;
  int listen_sd;
  int sd;
  struct sockaddr_in sa_serv;
  struct sockaddr_in sa_cli;
  size_t client_len;
  SSL_CTX* ctx;
  SSL*     ssl;
  X509*    client_cert;
  char*    str;
  char     buf [4096];
  SSL_METHOD *meth;
  int i;
  
  /* SSL preliminaries. We keep the certificate and key with the context. */

  SSL_load_error_strings(); // readable error messages
  SSLeay_add_ssl_algorithms();
  meth = SSLv23_server_method(); //  specify this is server
  ctx = SSL_CTX_new (meth);
  if (!ctx) {
    ERR_print_errors_fp(stderr);
    exit(2);
  }

	// Will not verify the client
  SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,NULL);
  // Set the location of the CA certificate
  SSL_CTX_load_verify_locations(ctx,CACERT,NULL);
  
  if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(3);
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(4);
  }

  if (!SSL_CTX_check_private_key(ctx)) {
    fprintf(stderr,"Private key does not match the certificate public key\n");
    exit(5);
  }

  /* ----------------------------------------------- */
  /* Prepare TCP socket for receiving connections */

  listen_sd = socket (AF_INET, SOCK_STREAM, 0);   CHK_ERR(listen_sd, "socket");
  
  memset (&sa_serv, '\0', sizeof(sa_serv));
  sa_serv.sin_family      = AF_INET;
  sa_serv.sin_addr.s_addr = INADDR_ANY;
  sa_serv.sin_port        = htons (1111);          /* Server Port number */
  
  err = bind(listen_sd, (struct sockaddr*) &sa_serv,
	     sizeof (sa_serv));                   CHK_ERR(err, "bind");
	     
  /* Receive a TCP connection. */
	     
  err = listen (listen_sd, 5);                    CHK_ERR(err, "listen");
  
  client_len = sizeof(sa_cli);
  sd = accept (listen_sd, (struct sockaddr*) &sa_cli, &client_len);
  CHK_ERR(sd, "accept");
  close (listen_sd);

  printf ("Connection from %lx, port %x\n",
	  sa_cli.sin_addr.s_addr, sa_cli.sin_port);
  
  /* ----------------------------------------------- */
  /* TCP connection is ready. Do server side SSL. */

  ssl = SSL_new (ctx);                           CHK_NULL(ssl);
  SSL_set_fd (ssl, sd);
  err = SSL_accept (ssl);                        CHK_SSL(err);
  
  /* Get the cipher - opt */
  printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
  
  /* Get client's certificate ( username & password login) */
  FILE *fp;
  char username[15]; //client input
  char password[15]; // client input
  
  char fuser[15]; // in database
  char fsalt[SALTLEN]; // in database
  char fpwd[HASHLEN]; // in database
  
  char hass_password[HASHLEN]; // using sha256, 32 byte
  
  fp = fopen("login.txt","r");
  if (fp == NULL) {
  		printf("Open file failed.\n");
        exit(EXIT_FAILURE);
  }
  
  // Receive client username & check user exist
  err = SSL_write (ssl, "Enter login username:", strlen("Enter login username:"));  CHK_SSL(err);
  err = SSL_read (ssl, username, sizeof(username) - 1);                     		CHK_SSL(err);
  username[err] = '\0';
  
  int flag = 0;
  while( fscanf(fp, "%s %s %s", fuser, fsalt, fpwd) != EOF) {
  		if ( strcmp(username, fuser) == 0) {
  			flag = 1;
  			printf("User exist in database!\n");
  			printf("User %s, salt %s, hashed pass:%s\n",fuser,fsalt,fpwd);
  			break;
  		}
  }
  
  if (flag == 0) {
  	printf(" User doesn't exist!");
  	close(sd);
  	SSL_free(ssl);
  	exit(1);
  }
  fclose(fp);
  
  // Receive client password
  err = SSL_write (ssl, "Enter password:", strlen("Enter password:"));  			CHK_SSL(err);
  err = SSL_read (ssl, password, sizeof(password) - 1);                     		CHK_SSL(err);
  password[err] = '\0';
  char tmptohash[30]; // (salt + password), to be hashed
  strcpy(tmptohash, fsalt);
  strcat(tmptohash, password);

  unsigned char temphash[HASHLEN];  // result of hash(salt + password)
  sha256(tmptohash, temphash);
  
  char fbuff[250];
  int cmp = 0;
  
  fp = fopen("tmp", "w+");
  for( i = 0; i < HASHLEN; i++) {
  	fprintf(fp, "%02x", temphash[i]); // Converting temphash(user input's hash) to characters in txt, for comparing purpose
  } 
  fprintf(fp, "\n");
  fclose(fp);
  
  fp = fopen("tmp", "r");
  fscanf(fp, "%s", fbuff);
  fclose(fp);
  
  // Comparing pwd hash values
  for(i = 0; i < HASHLEN; i++) {
  	if (fbuff[i] != fpwd[i]) {
  		printf("Mismatch at %c and %c",fbuff[i],fpwd[i]);
  		cmp = 1;
  	}
  }
  
  if (cmp == 1) {
  	err = SSL_write (ssl, "Wrong password! ", strlen("Wrong password!"));  			CHK_SSL(err);
  	printf("Wrong password for user.\n");
  	close(sd);
  	SSL_free(ssl);
  	exit(1);
  } 
  
  err = SSL_write (ssl, "Client authentication succeed!", strlen("Client authentication succeed!"));  			CHK_SSL(err);
  




  err = SSL_read (ssl, buf, sizeof(buf) - 1);                   CHK_SSL(err);
  buf[err] = '\0';
  printf ("Got %d chars:'%s'\n", err, buf);
  
  err = SSL_write (ssl, "I hear you.", strlen("I hear you."));  CHK_SSL(err);

  /* Clean up. */

  close (sd);
  SSL_free (ssl);
  SSL_CTX_free (ctx);

  return 0;
}
/* EOF - serv.cpp */
