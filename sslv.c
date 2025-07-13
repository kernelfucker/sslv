/* See LICENSE file for license details */
/* sslv - ssl vulnerability scanner */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/x509v3.h>

#define dp 443
#define dt 4

#define version "0.1"

typedef struct{
	char *hostname;
	int port;
	int timeout;
	int verbose;
	int c_all;
	int c_heartbleed;
	int c_poodle;
	int c_ccs;
	int c_freak;
	int c_logjam;
	int c_drown;
	int c_weak_ciphers;
	int c_certificate;
} LastOptions;

void init_ossl(){
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

void cleanup_ossl(){
	EVP_cleanup();
}

SSL_CTX *create_ssl_ctx(){
	const SSL_METHOD *m = TLS_client_method();
	SSL_CTX *c = SSL_CTX_new(m);
	if(!c){
		perror("unable to create ssl context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	SSL_CTX_set_options(c, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1);

	return c;
}

int connect_to_host(const char *hostname, int port, int timeout){
	struct hostent *host;
	struct sockaddr_in addr;
	int s = 1;
	struct timeval t;
	if((host = gethostbyname(hostname))){
		s = socket(PF_INET, SOCK_STREAM, 0);
		if(s < 0){
			perror("unable to create socket");
			return -1;
		}

		t.tv_sec = timeout;
		t.tv_usec = 0;
		setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&t, sizeof(t));
		setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&t, sizeof(t));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		addr.sin_addr.s_addr = *(long *)(host->h_addr);
		if(connect(s, (struct sockaddr *)&addr, sizeof(addr))){
			perror("unable to connect");
			close(s);
			return -1;
		}
	}

	return s;
}

void c_heartbleed(SSL *s, LastOptions *opts){
	if(!opts->c_all && !opts->c_heartbleed) return;
	printf("\n[+] checking for heartbleed vulnerability, cve-2014-0160\n");
	unsigned char hb[] = {
		0x18,
		0x03, 0x02,
		0x00, 0x03,
		0x01,
		0x40, 0x00
	};

	int r = SSL_write(s, hb + 5, sizeof(hb) - 5);
	if(r < 0){
		printf("[!] failed to send heartbeat request\n");
		return;
	}

	unsigned char buf[65535];
	r = SSL_read(s, buf, sizeof(buf));
	if(r > 3){
		printf("[+] received %d bytes\n", r);
	} else if(r >= 0){
		printf("[+] not vulnerable to heartbleed\n");
	} else {
		printf("[!] no heartbeat response, invulnerable\n");
	}
}

void c_poodle(SSL *s, LastOptions *opts){
	if(!opts->c_all && !opts->c_poodle) return;
	printf("\n[+] checking for poodle vulnerability, cve-2014-3566\n");

	SSL_CTX *c = SSL_get_SSL_CTX(s);

	long opts_bef = SSL_CTX_get_options(c);
	SSL_CTX_set_options(c, opts_bef & ~SSL_OP_NO_SSLv3);
	SSL *st = SSL_new(c);
	SSL_set_fd(st, SSL_get_fd(s));

	int r = SSL_connect(st);
	if(r <= 0){
		printf("[-] server does not support sslv3, not vulnerable to poodle\n");
	} else {
		printf("[+] server support sslv3, potentially vulnerable to poodle\n");
	}

	SSL_free(st);
	SSL_CTX_set_options(c, opts_bef);
}

void c_ccs(SSL *s, LastOptions *opts){
	if(!opts->c_all && !opts->c_ccs) return;
	printf("\n[+] checking for ccs injection vulnerability, cve-2014, 0224\n");

	const SSL_CIPHER *ch = SSL_get_current_cipher(s);
	const char *ch_name = SSL_CIPHER_get_name(ch);
	if(strstr(ch_name, "exp") || strstr(ch_name, "adh") || strstr(ch_name, "null")){
		printf("[+] server is using weak cipher, %s, potentially vulnerable to ccs injection\n", ch_name);
	} else {
		printf("[-] server does not appear to be vulnerable to ccs injection\n");
	}
}

void c_freak(SSL *s, LastOptions *opts){
	if(!opts->c_all && !opts->c_freak) return;
	printf("\n[+] checking for freak vulnerability, cve-2015-0204\n");

	STACK_OF(SSL_CIPHER) *ch = SSL_get_ciphers(s);

	int num_ch = sk_SSL_CIPHER_num(ch);
	int f_export = 0;
	for(int i = 0; i < num_ch; i++){
		const SSL_CIPHER *c = sk_SSL_CIPHER_value(ch, i);
		const char *ch_name = SSL_CIPHER_get_name(c);
		if(strstr(ch_name, "exp")){
			printf("[+] found export-grade cipher: %s, potentially vulnerable to freak\n", ch_name);
			f_export = 1;
		}
	}

	if(!f_export){
		printf("[-] no export-grade ciphers found, not vulnerable to freak\n");
	}
}

void c_logjam(SSL *s, LastOptions *opts){
	if(!opts->c_all && !opts->c_logjam) return;
	printf("\n[+] checking for logjam vulnerability, cve-2015-4000\n");

	const SSL_CIPHER *ch = SSL_get_current_cipher(s);
	const char *ch_name = SSL_CIPHER_get_name(ch);
	if(strstr(ch_name, "dhe") || strstr(ch_name, "dh")){
		printf("[!] server uses diffie-helman key exchange, checking strength\n");
		int bits = SSL_CIPHER_get_bits(ch, NULL);
		if(bits < 2048){
			printf("[+] potentially weak diffie-helman parameters, %d bits\n", bits);
			printf("[+] logjam vulnerability possible, should be at least 2048 bits\n");
		} else {
			printf("[-] diffie-helman parameters appear strong, %d bits\n", bits);
		}

	} else {
		printf("[-] no diffie-helman key exchange found, not vulnerable to logjam\n");
	}
}

void c_drown(SSL *s, LastOptions *opts){
	if(!opts->c_all && !opts->c_drown) return;
	printf("\n[+] checking for drown vulnerability, cve-2016-0800\n");

	SSL_CTX *c = SSL_get_SSL_CTX(s);
	long opts_bef = SSL_CTX_get_options(c);
	SSL_CTX_set_options(c, opts_bef & ~SSL_OP_NO_SSLv2);
	SSL *st = SSL_new(c);
	SSL_set_fd(st, SSL_get_fd(s));
	int r = SSL_connect(st);
	if(r <= 0){
		printf("[-] server does not support sslv2, not vulnerable to drown\n");
	} else {
		printf("[+] server supports sslv2, potentially vulnerable to drown\n");
	}

	SSL_free(st);
	SSL_CTX_set_options(c, opts_bef);
}

void c_weak_ciphers(SSL *s, LastOptions *opts){
	if(!opts->c_all && !opts->c_weak_ciphers) return;
	printf("\n[+] checking for weak ciphers\n");

	STACK_OF(SSL_CIPHER) *ch = SSL_get_ciphers(s);
	int num_ch = sk_SSL_CIPHER_num(ch);
	int weak_f = 0;
	for(int i = 0; i < num_ch; i++){
		const SSL_CIPHER *c = sk_SSL_CIPHER_value(ch, i);
		const char *ch_name = SSL_CIPHER_get_name(c);
		if(strstr(ch_name, "null") ||
			strstr(ch_name, "exp") ||
			strstr(ch_name, "adh") ||
			strstr(ch_name, "rc4") ||
			strstr(ch_name, "des") ||
			strstr(ch_name, "md5")){

			printf("[+] weak cipher: %s\n", ch_name);
			weak_f = 1;
		}
	}

	if(!weak_f){
		printf("[-] no weak ciphers found\n");
	}
}

void c_certificate(SSL *s, LastOptions *opts){
	if(!opts->c_all && !opts->c_certificate) return;
	printf("\n[+] checking server certificate\n");

	X509 *cr = SSL_get_peer_certificate(s);
	if(!cr){
		printf("[+] no certificate presented by server\n");
		return;
	}

	ASN1_TIME *not_bef = X509_get_notBefore(cr);
	ASN1_TIME *not_aft = X509_get_notAfter(cr);
	printf("validity perioid:\n");
	printf("  not before:	%s\n", not_bef->data);
	printf("  not after:	%s\n", not_aft->data);

	X509_NAME *subject = X509_get_subject_name(cr);
	printf("subject: %s\n", X509_NAME_oneline(subject, 0, 0));

	X509_NAME *issuer = X509_get_issuer_name(cr);
	printf("issuer: %s\n", X509_NAME_oneline(issuer, 0, 0));

	EVP_PKEY *k = X509_get_pubkey(cr);
	int k_type = EVP_PKEY_id(k);
	int bits = EVP_PKEY_bits(k);
	printf("public key: ");
	switch(k_type){
		case EVP_PKEY_RSA:
			printf("rsa, %d bits\n", bits);
			if(bits < 2048){
				printf("[+] rsa key size, %d bits, is less than recommended 2048 bits\n", bits);
			}

			break;

		case EVP_PKEY_DSA:
			printf("dsa, %d bits\n", bits);
			if(bits < 2048){
				printf("[+] dsa key size, %d bits, is less than recommended 2048 bits\n", bits);
			}

			break;

		case EVP_PKEY_EC:
			printf("ec, %d bits\n", bits);
			if(bits < 256){
				printf("[+] ec key size, %d bits, is less than recommended 256 bits\n", bits);
			}

			break;

		default:
			printf("unknown type, %d bits\n", bits);
	}

	int sign = X509_get_signature_nid(cr);
	printf("signature algorithm: %s\n", OBJ_nid2ln(sign));
	if(sign == NID_md5WithRSAEncryption || sign == NID_sha1WithRSAEncryption){
		printf("[+] weak signature algorithm, %s\n", OBJ_nid2ln(sign));
	}

	X509_free(cr);
	EVP_PKEY_free(k);
}

void last_host(LastOptions *opts){
	printf("scanning %s:%d\n", opts->hostname, opts->port);
	int sock = connect_to_host(opts->hostname, opts->port, opts->timeout);
	if(sock < 0){
		fprintf(stderr, "failed to connect to %s:%d\n", opts->hostname, opts->port);
		return;
	}

	SSL_CTX *c = create_ssl_ctx();
	SSL *s = SSL_new(c);
	SSL_set_fd(s, sock);
	if(SSL_connect(s) <= 0){
		ERR_print_errors_fp(stderr);
		SSL_free(s);
		close(sock);
		SSL_CTX_free(c);

		return;
	}

	printf("\n[+] ssl/tls connection established\n");
	printf("protocol: %s\n", SSL_get_version(s));
	printf("cipher: %s\n", SSL_get_cipher(s));

	c_heartbleed(s, opts);
	c_poodle(s, opts);
	c_ccs(s, opts);
	c_freak(s, opts);
	c_logjam(s, opts);
	c_drown(s, opts);
	c_weak_ciphers(s, opts);
	c_certificate(s, opts);

	SSL_shutdown(s);
	SSL_free(s);
	close(sock);
	SSL_CTX_free(c);
}

void show_version(){
	printf("sslv-%s\n", version);
}

void help(){
	printf("usage: sslv [options]..\n");
	printf("options:\n");
	printf("  -p	specify port, default is 443\n");
	printf("  -t	connection timeout, default is 4\n");
	printf("  -r	verbose output\n");
	printf("  -a	check all vulnerabilities, thats default\n");
	printf("  -b	check for heartbleed vulnerability\n");
	printf("  -o	check for poodle vulnerability\n");
	printf("  -c	check for ccs injection vulnerability\n");
	printf("  -f	check for freak vulnerability\n");
	printf("  -l	check for logjam vulnerability\n");
	printf("  -d	check for drown vulnerability\n");
	printf("  -w	check for weak ciphers\n");
	printf("  -e	check certificate validity\n");
	printf("  -v	show version information\n");
	printf("  -h	display this\n");
}

int main(int argc, char *argv[]){
	LastOptions opts = {
		.hostname = NULL,
		.port = dp,
		.timeout = dt,
		.verbose = 0,
		.c_all = 1,
		.c_heartbleed = 0,
		.c_poodle = 0,
		.c_ccs = 0,
		.c_freak = 0,
		.c_logjam = 0,
		.c_drown = 0,
		.c_weak_ciphers = 0,
		.c_certificate = 0,
	};

	int opt;
	while((opt = getopt(argc, argv, "p:t:rabo:cfldwevh")) != -1){
		switch(opt){
		case 'p':
			opts.port = atoi(optarg);
			break;
		case 't':
			opts.timeout = atoi(optarg);
			break;
		case 'r':
			opts.verbose = 1;
			break;
		case 'a':
			opts.c_all = 1;
			break;
		case 'b':
			opts.c_heartbleed = 1;
			opts.c_all = 0;
			break;
		case 'o':
			opts.c_poodle = 1;
			opts.c_all = 0;
			break;
		case 'c':
			opts.c_ccs = 1;
			opts.c_all = 0;
			break;
		case 'f':
			opts.c_freak = 1;
			opts.c_all = 0;
			break;
		case 'l':
			opts.c_logjam = 1;
			opts.c_all = 0;
			break;
		case 'd':
			opts.c_drown = 1;
			opts.c_all = 0;
			break;
		case 'w':
			opts.c_weak_ciphers = 1;
			opts.c_all = 0;
			break;
		case 'e':
			opts.c_certificate = 1;
			opts.c_all = 0;
			break;
		case 'v':
			show_version();
			exit(0);
		case 'h':
			help();
			exit(0);
		default:
			help();
			exit(EXIT_FAILURE);
		}
	}

	if(optind < argc){
		opts.hostname = argv[optind];
	} else {
		help();
		exit(EXIT_FAILURE);
	}

	init_ossl();
	last_host(&opts);
	cleanup_ossl();

	return 0;
}
