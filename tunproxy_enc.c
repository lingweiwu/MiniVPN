/*
 * tunproxy.c --- small demo program for tunneling over UDP with tun/tap
 *
 * Copyright (C) 2003  Philippe Biondi <phil@secdev.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */
 
 /* Edited:
  * tunproxy_enc.c --- add encryption/HMAC for UDP tunnel
  * 2016 Spring, Syracuse University
  */

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <stdlib.h>

//encrpyt
#include <openssl/evp.h>
//hmac
#include <openssl/hmac.h>
//#include <openssl/x509.h>

#define PERROR(x) do { perror(x); exit(1); } while (0)
#define ERROR(x, args ...) do { fprintf(stderr,"ERROR:" x, ## args); exit(1); } while (0)

#define ENC 1
#define DEC 0

char MAGIC_WORD[] = "Wazaaaaaaaaaaahhhh !";


int do_crypt(char *input, int inlen, char *output, int do_encrypt)
{
    unsigned char outbuf[1024];
    int outlen, padlen;
    EVP_CIPHER_CTX *ctx;

    unsigned char key[16] = {0x8d,0x20,0xe5,0x05,0x6a,0x8d,0x24,0xd0,0x46,0x2c,0xe7,0x4e,0x49,0x04,0xc1,0xb5};
    unsigned char iv[16];

    memset(iv,0,sizeof(iv));

    memset(outbuf,0,sizeof(outbuf));

    ctx = EVP_CIPHER_CTX_new();
    
     //do_encrypt = 0:1? decrypt,encrypt.
    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, do_encrypt);

    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

    /* encrypt/decrpyt the plaintext*/
	if(!EVP_CipherUpdate(ctx, outbuf, &outlen, input, inlen)) 
	{
		/* Error */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
	}

	/* encrypt/decrpyt the padding part*/
	if(!EVP_CipherFinal_ex(ctx, outbuf + outlen, &padlen))	
	{
		/* Error */
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}

	outlen += padlen; // total length of ciphertext

	memcpy(output,outbuf,outlen);

	EVP_CIPHER_CTX_free(ctx);
    return 1;
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
char *output)
{
    //HMAC_CTX *ctx;
    unsigned char md_value[EVP_MAX_MD_SIZE];  //32 byte
    unsigned int md_len;
    
    HMAC(EVP_sha256(), key, key_len, data, data_len, md_value, md_len);

    // HMAC_Init_ex(ctx,key,strlen(key),EVP_sha256(),NULL);

    // /*hash the data*/
    // if(!HMAC_Update(ctx, data, data_len)) {
    //     /* Error */
    //     HMAC_CTX_free(ctx);
    //     return 0;
    // }

    // /*hash the padding*/
    // if(!HMAC_Final(ctx, md_value, md_len)) {
    //     /* Error */
    //     HMAC_CTX_free(ctx);
    //     return 0;
    // }

    memcpy(output,md_value,md_len);

    //HMAC_CTX_free(ctx);
    return 1;
}

void test_foo () {
	char testbuf[] = {'T','h','i','s',' ','i','s',' ','a',' ','t','o','p',' ','s','e','c','r','e','t','.'};
	char test_cipher[2000];
	char test_decipher[2000];
	int len, len2;
    char test_hash[32];

    unsigned char key[16] = {0x8d,0x20,0xe5,0x05,0x6a,0x8d,0x24,0xd0,0x46,0x2c,0xe7,0x4e,0x49,0x04,0xc1,0xb5};

	printf("Before cipher, testbuf is %s\n",testbuf);

	len = strlen(testbuf);
	if (do_crypt(testbuf,len, test_cipher, ENC)) {
		printf ("Test encrypt succeeded!\n");
		printf("During, test_cipher is %s\n",test_cipher);
	} else {printf ("Test encrypt error!\n");}
	
	len2 = strlen(test_cipher);
	do_crypt(test_cipher,len2, test_decipher, DEC);

	printf("After decipher, test_decipher is %s \n",test_decipher);

    //test hash
    if(hmac(testbuf,len,key,strlen(key),test_hash)) {
        printf ("Test hmac_sha256 succeeded!\n");
        printf("Hash value is %s\n",test_hash);
    } else {
        printf (" Hash error!\n");
    }
}

void usage()
{
    fprintf(stderr, "Usage: tunproxy [-s port|-c targetip:port] [-e]\n");
    exit(0);
}

int main(int argc, char *argv[])
{
    struct sockaddr_in sin, sout, from;
    struct ifreq ifr;
    int fd, s, fromlen, soutlen, port, PORT, l;
    char c, *p, *ip;
    char buf[2000];
    fd_set fdset;

    //hard-coded key
    unsigned char key[16] = {0x8d,0x20,0xe5,0x05,0x6a,0x8d,0x24,0xd0,0x46,0x2c,0xe7,0x4e,0x49,0x04,0xc1,0xb5};
    
    int MODE = 0, TUNMODE = IFF_TUN, DEBUG = 0;
    
    while ((c = getopt(argc, argv, "s:c:ehd")) != -1) {
        switch (c) {
            case 'h':
                usage();
            case 'd':
                DEBUG++;
                break;
            case 's':
                MODE = 1;
                PORT = atoi(optarg);
                break;
            case 'c':
                MODE = 2;
                p = memchr(optarg,':',16);
                if (!p) ERROR("invalid argument : [%s]\n",optarg);
                *p = 0;
                ip = optarg;
                port = atoi(p+1);
                PORT = 0;
                break;
            case 'e':
                TUNMODE = IFF_TAP;
                break;
            default:
                usage();
        }
    }
    if (MODE == 0) usage();
    
    if ( (fd = open("/dev/net/tun",O_RDWR)) < 0) PERROR("open");

	////////////////////////TEST
	//test_foo();
    ////////////////////////

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
            printf("Bad magic word from %s:%i\n",
                   inet_ntoa(from.sin_addr.s_addr), ntohs(from.sin_port));
        }
        l = sendto(s, MAGIC_WORD, sizeof(MAGIC_WORD), 0, (struct sockaddr *)&from, fromlen);
        if (l < 0) PERROR("sendto");
    } else {
        from.sin_family = AF_INET;
        from.sin_port = htons(port);
        inet_aton(ip, &from.sin_addr);
        l =sendto(s, MAGIC_WORD, sizeof(MAGIC_WORD), 0, (struct sockaddr *)&from, sizeof(from));
        if (l < 0) PERROR("sendto");
        l = recvfrom(s,buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
        if (l < 0) PERROR("recvfrom");
        if (strncmp(MAGIC_WORD, buf, sizeof(MAGIC_WORD) != 0))
            ERROR("Bad magic word for peer\n");
    }
    printf("Connection with %s:%i established\n",
           inet_ntoa(from.sin_addr.s_addr), ntohs(from.sin_port));
    
    while (1) {
        FD_ZERO(&fdset);
        FD_SET(fd, &fdset);
        FD_SET(s, &fdset);
        if (select(fd+s+1, &fdset,NULL,NULL,NULL) < 0) PERROR("select");
        if (FD_ISSET(fd, &fdset)) {
            if (DEBUG) write(1,">", 1);
            l = read(fd, buf, sizeof(buf));
            if (l < 0) PERROR("read");
            if (sendto(s, buf, l, 0, (struct sockaddr *)&from, fromlen) < 0) PERROR("sendto");
        } else {
            if (DEBUG) write(1,"<", 1);
            l = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&sout, &soutlen);
            if ((sout.sin_addr.s_addr != from.sin_addr.s_addr) || (sout.sin_port != from.sin_port))
                printf("Got packet from  %s:%i instead of %s:%i\n", 
                       inet_ntoa(sout.sin_addr.s_addr), ntohs(sout.sin_port),
                       inet_ntoa(from.sin_addr.s_addr), ntohs(from.sin_port));
            if (write(fd, buf, l) < 0) PERROR("write");
        }
        
    }
}
