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

    //unsigned char key[16] = {0x8d,0x20,0xe5,0x05,0x6a,0x8d,0x24,0xd0,0x46,0x2c,0xe7,0x4e,0x49,0x04,0xc1,0xb5};
    //unsigned char iv[16];

    //memset(iv,0,sizeof(iv));

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

void test_foo () {
	//char testbuf[] = "asdfasdfasfdf  afds sdafs";
	char testbuf[] = "Ishmael believes he has signed onto a routine commission aboard a normal whaling vessel, but he soon learns that Captain Ahab is not guiding the Pequod in the simple pursuit of commerce but is seeking one specific whale, Moby-Dick, a great while whale infamous for his giant size and his ability to destroy the whalers that seek him. Captain Ahab's wooden leg is the result of his first encounter with the whale, when he lost both leg and ship. After the ship sails it becomes clear that Captain Ahab is bent on revenge and he intends to get Moby-Dick.";
	char test_cipher[1024];
	char test_decipher[1024];
	int len, len2, len3, i;
    char test_hash[32],test_hash2[32];

    unsigned char key[16] = {0x8d,0x20,0xe5,0x05,0x6a,0x8d,0x24,0xd0,0x46,0x2c,0xe7,0x4e,0x49,0x04,0xc1,0xb5};
    unsigned char iv[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16};

	printf("Before cipher, testbuf is %s\n",testbuf);

	len = strlen(testbuf);
	len2 = do_crypt(testbuf,len, test_cipher, key, iv, ENC);
	printf("TEST: len2 is %d \n",len2);
	printf("TEST: After cipher, test_cipher is %s \n",test_cipher);
	len3 = do_crypt(test_cipher,len2, test_decipher, key, iv, DEC);
	printf("TEST: After decipher, test_decipher is %s \n",test_decipher);

    //test hash
//     if(hmac(testbuf,len,key,strlen(key),test_hash)) {
//         printf ("Test hmac_sha256 succeeded!\n");
//         for ( i = 0; i < strlen (test_hash); i++) {
//             	printf("%02x",test_hash[i]);
//             }
//             printf("\n");
//     } else {
//         printf (" Hash error!\n");
//     }
//     
//     hmac(testbuf,len,key,strlen(key),test_hash2);
//     if(!memcmp(test_hash,test_hash2,32)) {
//      	printf (" Hash compare are equal!!!!!\n");
//     }
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

    //hard-coded key & iv
    unsigned char key[16] = {0x8d,0x20,0xe5,0x05,0x6a,0x8d,0x24,0xd0,0x46,0x2c,0xe7,0x4e,0x49,0x04,0xc1,0xb5};
    unsigned char iv[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16};
    // printf("hardcoded iv: ");  
//   	for( i =0;i < strlen(iv); i++)  
//       	printf("%.02x", iv[i]);  
// 	printf("\n");
    
    
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
            
            printf("-----SEND: Original buf:");
            for( i = 0;i < l; i++)  
				printf("%.02x", buf[i]);  
			printf("\n");
            
            /* Reconstruct send buf */
            // 1. iv (length = 16)
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
