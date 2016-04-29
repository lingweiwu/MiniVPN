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

#define ENC 1
#define DEC 0

#define PERROR(x) do { perror(x); exit(1); } while (0)
#define ERROR(x, args ...) do { fprintf(stderr,"ERROR:" x, ## args); exit(1); } while (0)

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

char MAGIC_WORD[] = "Wazaaaaaaaaaaahhhh !";

unsigned char * rand_N (const int N) {
    unsigned char seed[N];
    size_t l;
    
    FILE* urandom = fopen("/dev/urandom","r");
    l = fread(&seed, sizeof(char), N, urandom);
    if (l == NULL) { printf ("Read from urandom error!\n"); return NULL;}
    
    while (l < N) {
        printf("No enough randomness in urandom. Move your mouse!\n");
        l = fread(&seed, sizeof(char), N, urandom);
    }
    
    fclose(urandom);
    return seed;
}

/*
 * Encrypt/decrypt
 *
 * Succeed:
 * return output length
 * Failed:
 * return 0
 */
int do_crypt(char *input, int inlen, char *output, const unsigned char *key, const unsigned char *iv, int do_encrypt)
{
    unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int outlen, padlen;
    EVP_CIPHER_CTX ctx;
    
    EVP_CIPHER_CTX_init(&ctx);
    
    EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, NULL, NULL, do_encrypt);
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(&ctx) == 16);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(&ctx) == 16);
    
    EVP_CipherInit_ex(&ctx, NULL, NULL, key, iv, do_encrypt);
    
    //printf("-----CRYPT: inlen:%d\n\n",inlen);
    
    /* encrypt/decrpyt the plaintext*/
    if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, input, inlen))
    {
        /* Error */
        EVP_CIPHER_CTX_cleanup(&ctx);
        return -1;
    }
    
    /* encrypt/decrpyt the padding part*/
    if(!EVP_CipherFinal_ex(&ctx, outbuf + outlen, &padlen))
    {
        /* Error */
        EVP_CIPHER_CTX_cleanup(&ctx);
        return -1;
    }
    
    outlen += padlen; // total length of ciphertext
    
    memcpy(output,outbuf,outlen);
    //printf("-----CRYPT: outlen:%d\n\n",outlen);
    EVP_CIPHER_CTX_cleanup(&ctx);
    return outlen;
}

/*
 * the HMAC_SHA256 transform looks like:
 *
 * SHA256(K XOR opad, SHA256(K XOR ipad, text))
 *
 * where K is an n byte key
 * ipad is the byte 0x36 repeated 64 times
 * opad is the byte 0x5c repeated 64 times
 * and text is the data being protected
 */
int hmac(
         const unsigned char *data,      /* pointer to data stream        */
         int                 data_len,   /* length of data stream         */
         const unsigned char *key,       /* pointer to authentication key */
         int                 key_len,    /* length of authentication key  */
         char 				*output)
{
    unsigned char md_value[EVP_MAX_MD_SIZE];  //32 byte
    unsigned int md_len;
    
    HMAC(EVP_sha256(), key, key_len, data, data_len, md_value, &md_len);
    
    memcpy(output,md_value,md_len);
    
    return 1;
}


/*  tunproxy.c
 *  UDP tunnel
 */
int tunproxy(char *server_ip, char *server_port)
{
    struct sockaddr_in sin, sout, from;
    struct ifreq ifr;
    int fd, s, fromlen, soutlen, port, PORT, l;
    char c, *p, *ip;
    unsigned char buf[2000],sendbuf[2000],databuf[2000],tempbuf[2000], hashbuf[32];
    fd_set fdset;
    int i, crypt_len;
    
    // Generate random key
    unsigned char key[16];
    
    memset(key,0,strlen(key));
    memcpy(key,rand_N(16),16);
    while(strlen(key) < 16) {
        printf("Not enough randomness to generate key, move your mouse!!\n");
        memcpy(key,rand_N(16),16);
    }
    
    // iv
    unsigned char iv[16];
    memset(iv,0,strlen(iv));
    
    int MODE = 0, TUNMODE = IFF_TUN, DEBUG = 1;
    
    char arg[20];
    strcpy(arg,server_ip);
    strcat(arg,":");
    strcat(arg,server_port);
    
    /* Client */
    MODE = 2;
    p = memchr(arg,':',16);
	if (!p) ERROR("invalid argument : [%s]\n",arg);
	*p = 0;
	ip = arg;
	port = atoi(p+1);
	PORT = 0;
	
    
//     while ((c = getopt(argc, argv, "s:c:ehd")) != -1) {
//         switch (c) {
//             case 'h':
//                 //usage();
//             case 'd':
//                 DEBUG++;
//                 break;
//             case 's':
//                 MODE = 1;
//                 PORT = atoi(optarg);
//                 break;
//             case 'c':
//                 MODE = 2;
//                 p = memchr(optarg,':',16);
//                 if (!p) ERROR("invalid argument : [%s]\n",optarg);
//                 *p = 0;
//                 ip = optarg;
//                 port = atoi(p+1);
//                 PORT = 0;
//                 break;
//             case 'e':
//                 TUNMODE = IFF_TAP;
//                 break;
//             default:
//                 //usage();
//         }
//     }
//     if (MODE == 0) usage();

    
    if ( (fd = open("/dev/net/tun",O_RDWR)) < 0) PERROR("open");
    
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = TUNMODE;
    strncpy(ifr.ifr_name, "toto%d", IFNAMSIZ);
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) PERROR("ioctl");
    
    printf("Allocated interface %s. Configure and use it\n", ifr.ifr_name);
    
    s = socket(PF_INET, SOCK_DGRAM, 0);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(PORT);
    if ( bind(s,(struct sockaddr *)&sin, sizeof(sin)) < 0) PERROR("bind");
    
    fromlen = sizeof(from);
    
    if (MODE == 1) {
        while(1) {
            l = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
            if (l < 0) PERROR("recvfrom");
            if (strncmp(MAGIC_WORD, buf, sizeof(MAGIC_WORD)) == 0)
                break;
            //printf("Bad magic word from %s:%i\n",
            //       inet_ntoa(from.sin_addr.s_addr), ntohs(from.sin_port));
            printf("Bad magic word\n");
        }
        l = sendto(s, MAGIC_WORD, sizeof(MAGIC_WORD), 0, (struct sockaddr *)&from, fromlen);
        if (l < 0) PERROR("sendto");
    } else {
    	
        printf("---TUN CLI #1:In IF\n");
        from.sin_family = AF_INET;
        from.sin_port = htons(port);
        inet_aton(ip, &from.sin_addr);
         printf("---TUN CLI #2:Before sendto\n");
        l =sendto(s, MAGIC_WORD, sizeof(MAGIC_WORD), 0, (struct sockaddr *)&from, sizeof(from));
        if (l < 0) { PERROR("sendto"); printf("---TUN CLI #3:Sendto error\n");}
        l = recvfrom(s,buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
        if (l < 0) {PERROR("recvfrom"); printf("---TUN CLI #4:Recvfrom error\n");}
        if (strncmp(MAGIC_WORD, buf, sizeof(MAGIC_WORD) != 0))
            ERROR("Bad magic word for peer\n");
        printf("---TUN CLI #5:after sending magic word?!\n");
    }
    //printf("Connection with %s:%i established\n",
    //       inet_ntoa(from.sin_addr.s_addr), ntohs(from.sin_port));
    printf("Connection estbalished.\n");
    
    while (1) {
        FD_ZERO(&fdset);
        FD_SET(fd, &fdset);
        FD_SET(s, &fdset);
        if (select(fd+s+1, &fdset,NULL,NULL,NULL) < 0) PERROR("select");
        if (FD_ISSET(fd, &fdset)) {
            if (DEBUG) write(1,">", 1);
            l = read(fd, buf, sizeof(buf));
            if (l < 0) PERROR("read");
            
            printf("-----SEND: Original buf:");
            for( i = 0;i < l; i++)
                printf("%.02x", buf[i]);
            printf("\n");
            
            /* Reconstruct send buf */
            // 1. iv (length = 16)
            memset(iv,0,strlen(iv));
            memcpy(iv,rand_N(16),16);
            while(strlen(iv) < 16) {
                printf("Not enough randomness to generate iv, move your mouse!!\n");
                memcpy(iv,rand_N(16),16);
            }
            strncpy(sendbuf, iv, 16);
            // 2. encrypt data
            crypt_len = do_crypt(buf, l, tempbuf, key, iv, ENC);
            if (crypt_len < 0) {
                /* Crypt Error */
                PERROR("encrpyt");
                continue;
            }
            printf("-----SEND: crypt_len = %d\n", crypt_len);
            memcpy(sendbuf + 16, tempbuf, crypt_len);
            // 3. hash (hash iv + cipher data)  (length = 32)
            hmac(sendbuf, crypt_len + 16, key, strlen(key), tempbuf);
            memcpy(sendbuf + 16 + crypt_len, tempbuf, 32);
            
            printf("-----SEND: sendbuf length should be = %d\n",crypt_len + 16 + 32);
            printf("-----SEND: strlen(sendbuf) = %d\n",strlen(sendbuf));
            printf ("-----SEND: sendbuf:%s\n",sendbuf);
            
            if (sendto(s, sendbuf, crypt_len + 16 + 32, 0, (struct sockaddr *)&from, fromlen) < 0) PERROR("sendto");
        } else {
            if (DEBUG) write(1,"<", 1);
            l = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&sout, &soutlen);
            printf ("-----RECV: l = %d\n", l);
            if ((sout.sin_addr.s_addr != from.sin_addr.s_addr) || (sout.sin_port != from.sin_port))
                //printf("Got packet from  %s:%i instead of %s:%i\n",
                //       inet_ntoa(sout.sin_addr.s_addr), ntohs(sout.sin_port),
                //       inet_ntoa(from.sin_addr.s_addr), ntohs(from.sin_port));
            printf ("Got packet.\n");
            printf ("-----RECV: received buf:%s\n", buf);
            
            /* Get recv buf */
            // 1. get signature
            memcpy(hashbuf, buf + l - 32, 32);
            // 2. check signature
            hmac(buf, l - 32, key, strlen(key), tempbuf);
            if(memcmp(hashbuf, tempbuf, 32) != 0) {
                printf ("-----RECV: Hash compare are equal!\n");
                memset(tempbuf,0,sizeof(tempbuf));
                // 3. get iv
                strncpy(iv, buf, 16);
                // 4. decrypt data
                crypt_len = do_crypt(buf + 16, l - 32 - 16, databuf, key, iv, DEC);
                
                printf("-----RECV: Original buf:");
                for( i = 0;i < crypt_len; i++)  
                    printf("%.02x", databuf[i]);  
                printf("\n");
                
                // 5. write decrypted data to fd
                if (write(fd, databuf, crypt_len) < 0) PERROR("write");	
            } else {
                printf ("-----RECV: Hash compare failed, discard!\n");
            } 
        }
    }
}

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
    
    /// Reuse address
    int ret;
    int one = 1;
    ret = setsockopt( sd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one) );
    
    memset (&sa, '\0', sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = inet_addr ("172.16.20.179");   /* Server IP */
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
    
    /*-------------------------------------------------*/
    /* Establishing UDP tunnel in child process */
    int pipe_fd[2];
    pipe2(pipe_fd,O_NONBLOCK);
    int pid = fork();
    
    
    if(pid == 0) { 		// handle TCP tunnel
        /* --------------------------------------------------- */
        /* DATA EXCHANGE - Send a message and receive a reply. */
        printf(">>>>>I am in pid #0, TCP tunnel?\n");
        
//         err = SSL_write (ssl, "Hello World!", strlen("Hello World!"));  CHK_SSL(err);
//         
//         err = SSL_read (ssl, buf, sizeof(buf) - 1);                     CHK_SSL(err);
//         buf[err] = '\0';
//         printf ("Got %d chars:'%s'\n", err, buf);
//         SSL_shutdown (ssl);  /* send SSL/TLS close_notify */
//         
       /* Clean up. */
         
         close (sd);
         SSL_free (ssl);
         SSL_CTX_free (ctx);
//         
         return 0;
        
    } 
    else if (pid > 0) { 	// handle UDP tunnel
        printf(">>>>>I am in pid #1, UDP tunnel?\n");
        char ip[20];
        char port[10];
        
        //scanf("Input (server ip : port #) to establish UDP tunnel:%s:%s\n",&ip,&port);
        tunproxy("172.16.20.179","45569");
        
        exit(1);
    } 
    else {
        /* Error */
        PERROR("fork");
        exit(1);
        
    }
    
    
    
    
    
    
}
/* EOF - cli.cpp */
