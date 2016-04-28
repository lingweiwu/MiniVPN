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
    char buf[2000],sendbuf[2000],databuf[2000],tempbuf[2000], hashbuf[32];
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
//     printf("key generated! length is:%d\n",strlen(key));
//     printf("Key is : ");
//     for( i = 0; i < strlen(key); i++)
//         printf("%.02x", key[i]);
//     printf("\n");

	// iv
	unsigned char iv[16];
	memset(iv,0,strlen(iv));
    
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
                printf("Got packet from  %s:%i instead of %s:%i\n", 
                       inet_ntoa(sout.sin_addr.s_addr), ntohs(sout.sin_port),
                       inet_ntoa(from.sin_addr.s_addr), ntohs(from.sin_port));
        	
        	printf ("-----RECV: received buf:%s\n", buf);
        	
        	/* Get recv buf */
        	// 1. get signature
        	memcpy(hashbuf, buf + l - 32, 32);
        	// 2. check signature
        	hmac(buf, l - 32, key, strlen(key), tempbuf);
			if(!memcmp(hashbuf, tempbuf, 32)) {
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
