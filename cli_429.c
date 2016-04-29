/* cli.cpp  -  Minimal ssleay client for Unix
   30.9.1996, Sampo Kellomaki <sampo@iki.fi> */

/* mangled to work with SSLeay-0.9.0b and OpenSSL 0.9.2b
   Simplified to be even more minimal
   12/98 - 4/99 Wade Scholine <wades@mail.cybg.com> */
   
/* CIS 644 Internet Security final project - MiniVPN
 * integrated with tunproxy to setup data transmission UDP tunnel with encryption/HMAC
 * Using IPC to manipulate SSL TCP tunnel & UDP tunnel
 * 2016/4/29, Lingwei Wu <lwu108@syr.edu>, Syracuse University
 */

#include <unistd.h>
#include <stdio.h>
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

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define CERTF "client.crt"
#define KEYF "client.key"
#define CACERT "ca.crt"


#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

int main ()
{
  int err;
  int sd;
  struct sockaddr_in sa;
  SSL_CTX* ctx;
  SSL*     ssl;
  X509*    server_cert;
  char*    str;
  char     buf [4096];
  SSL_METHOD *meth;

  SSLeay_add_ssl_algorithms();
  meth = SSLv23_client_method(); //  specify this is client
  SSL_load_error_strings(); // readable error messages
  ctx = SSL_CTX_new (meth);                        CHK_NULL(ctx);

  CHK_SSL(err);

  // Will verify the server
  SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
  // Set the location of the CA certificate
  SSL_CTX_load_verify_locations(ctx,CACERT,NULL);
  
  /* ----------------------------------------------- */
  /* Create a socket and connect to server using normal socket calls. */
  
  sd = socket (AF_INET, SOCK_STREAM, 0);       CHK_ERR(sd, "socket");
 
  memset (&sa, '\0', sizeof(sa));
  sa.sin_family      = AF_INET;
  sa.sin_addr.s_addr = inet_addr ("172.16.20.177");   /* Server IP */
  sa.sin_port        = htons     (1111);          /* Server Port number */
  
  err = connect(sd, (struct sockaddr*) &sa,
		sizeof(sa));                   CHK_ERR(err, "connect");

  /* ----------------------------------------------- */
  /* Now we have TCP conncetion. Start SSL negotiation. */
  
  ssl = SSL_new (ctx);                         CHK_NULL(ssl);    
  SSL_set_fd (ssl, sd);
  err = SSL_connect (ssl);                     CHK_SSL(err);
    
  /* Following two steps are optional and not required for
     data exchange to be successful. */
  
  /* Get the cipher - opt */
  printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
  
  /* Get server's certificate (note: beware of dynamic allocation) - opt */

  server_cert = SSL_get_peer_certificate (ssl);       CHK_NULL(server_cert);
  printf ("Server certificate:\n");
  
  str = X509_NAME_oneline (X509_get_subject_name (server_cert),0,0);
  CHK_NULL(str);
  printf ("\t subject: %s\n", str);
  OPENSSL_free (str);

  str = X509_NAME_oneline (X509_get_issuer_name  (server_cert),0,0);
  CHK_NULL(str);
  printf ("\t issuer: %s\n", str);
  OPENSSL_free (str);

  /* We could do all sorts of certificate verification stuff here before
     deallocating the certificate. */
  X509_free (server_cert);
  
  
  /* Certificate client: send username & password to login */
  // Get user login input
  char username[15];
  char password[15];
  
  // "Enter login username:" 
  err = SSL_read (ssl, buf, sizeof(buf) - 1);				CHK_SSL(err);
  buf[err] = '\0';
  printf ("%s\n", buf);  
  
  gets(username);
  err = SSL_write (ssl, username, strlen(username));		CHK_SSL(err);
  
  //"Enter password:"
  err = SSL_read (ssl, buf, sizeof(buf) - 1);				CHK_SSL(err);
  buf[err] = '\0';
  printf ("%s\n", buf); 
  
  gets(password);
  err = SSL_write (ssl, password, strlen(password));		CHK_SSL(err);
	
  
  // authentication outcome
  err = SSL_read (ssl, buf, sizeof(buf) - 1);				CHK_SSL(err);
  buf[err] = '\0';
  printf ("%s\n", buf); 


  
  /* --------------------------------------------------- */
  /* DATA EXCHANGE - Send a message and receive a reply. */

  err = SSL_write (ssl, "Hello World!", strlen("Hello World!"));  CHK_SSL(err);
  
  err = SSL_read (ssl, buf, sizeof(buf) - 1);                     CHK_SSL(err);
  buf[err] = '\0';
  printf ("Got %d chars:'%s'\n", err, buf);
  SSL_shutdown (ssl);  /* send SSL/TLS close_notify */

  /* Clean up. */

  close (sd);
  SSL_free (ssl);
  SSL_CTX_free (ctx);

  return 0;
}
/* EOF - cli.cpp */