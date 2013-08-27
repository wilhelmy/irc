/************************************************************************
 *   IRC - Internet Relay Chat, tproxy.c
 *   Copyright (C) 2009-2013 sd@hysteria.cz
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * Originally SSL has been implemented inside ircd process (-SD and
 * later -fic patches). However those are generally too dangerous.
 *
 * The state machine for SSL is rather complicated and prone to bugs,
 * including various cpu-bound exploits, such as renegotiation
 * (http://seclists.org/fulldisclosure/2011/Oct/779).
 *
 * This is why we do stuff in separate process now. The workflow is:
 * 1) IRCD accepts connection as per usual, does its stuff with the socket.
 *    When it notices the socket belongs to ssl P: line, hands the connection
 *    over to ssl process via send_fd(), ssl process gets it via receive_fd().
 * 2) SSL process, in turn, hands over cleartext pipe, again, via send_fd() 
 * 3) Additionaly, we run multiple ssl workers on smp machines further making
 *    things more scalable
 * 4) Context switch contention is not really an issue as scheduling tends
 *    to happen in bulk via select()/poll(), at least from cursory benchmarks
 *    on linux.
 *
 * This switcheroo logic greatly simplifies stuff and reduces amount of ircd
 * boilerplate, as otherwise we'd be forced to use additional connect/accept
 * state machine on both ends, including various special cases and wrappers
 * in IRCD code.
 *
 * If anything will go awry on the SSL side, it will simply kill everyone in
 * that given worker while the bulk of cleartext users remain unaffected.
 *
 * Extending this to S2S links is fairly trivial, however there is no demand
 * for that, yet.
 */

#include <assert.h>
#include "os.h"
#include "config.h"
#ifdef USE_TPROXY

#include <stdio.h>

#define report_error(fmt...) { fprintf(stderr, fmt); exit(1); }
#define FDSETSIZE FD_SETSIZE
#define BSIZE 512

#if 0
#undef TPROXY_NCPU
#define TPROXY_NCPU 1
FILE *logff = NULL;
#define DEBUG(fmt...) { int errsave = errno; stderr=logff;logff=logff?logff:fopen("/tmp/tproxy.log","w"); fprintf(logff, "%s:%d -> ", __func__, __LINE__); fprintf(logff, fmt); fprintf(logff, "\n"); fflush(logff); errno = errsave; }
#else
#define DEBUG(...) do {} while(0)
#endif

/***********************************************
 * openssl cruft
 ***********************************************/
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

#define KEY_CACHE_LENGTH 2049
#define KEY_CACHE_TIME 3600

#ifndef min
#define min(x,y) (((x)>(y))?(y):(x))
#endif

static unsigned char dh512_p[]={
	0xDA,0x58,0x3C,0x16,0xD9,0x85,0x22,0x89,0xD0,0xE4,0xAF,0x75,
	0x6F,0x4C,0xCA,0x92,0xDD,0x4B,0xE5,0x33,0xB8,0x04,0xFB,0x0F,
	0xED,0x94,0xEF,0x9C,0x8A,0x44,0x03,0xED,0x57,0x46,0x50,0xD3,
	0x69,0x99,0xDB,0x29,0xD7,0x76,0x27,0x6B,0xA2,0xD3,0xD4,0x12,
	0xE2,0x18,0xF4,0xDD,0x1E,0x08,0x4C,0xF6,0xD8,0x00,0x3E,0x7C,
	0x47,0x74,0xE8,0x33,
	};
static unsigned char dh512_g[]={
	0x02,
	};

static DH *get_dh512(void)
	{
	DH *dh=NULL;

	if ((dh=DH_new()) == NULL) return(NULL);
	dh->p=BN_bin2bn(dh512_p,sizeof(dh512_p),NULL);
	dh->g=BN_bin2bn(dh512_g,sizeof(dh512_g),NULL);
	if ((dh->p == NULL) || (dh->g == NULL))
		return(NULL);
	return(dh);
	}

/* this cruft is sometimes needed ;-( */
static inline RSA *make_temp_key(int keylen) {
#if SSLEAY_VERSION_NUMBER >= 0x0900
	return RSA_generate_key(keylen, RSA_F4, NULL, NULL);
#else
	return RSA_generate_key(keylen, RSA_F4, NULL);
#endif
}

static	RSA *tmp_rsa_cb(SSL *s, int export, int keylen) {
	static int 	initialized = 0;
	static struct keytabstruct {
		RSA 	*key;
	        time_t 	timeout;
	} keytable[KEY_CACHE_LENGTH];
	static RSA	*longkey = NULL;
	static int	longlen = 0;
	static time_t	longtime = 0;
	RSA		*oldkey, *retval;
	time_t		now;
	int 		i;

	if(!initialized) {
		for(i=0; i < KEY_CACHE_LENGTH; i++) {
			keytable[i].key = NULL;
			keytable[i].timeout = 0;
		}
		initialized=1;
	}
	time(&now);
	if(keylen < KEY_CACHE_LENGTH) {
        	if(keytable[keylen].timeout < now) {
			oldkey = keytable[keylen].key;
			keytable[keylen].key = make_temp_key(keylen);
			keytable[keylen].timeout=now + KEY_CACHE_TIME;
			if(oldkey)
				RSA_free(oldkey);
	        }
		retval=keytable[keylen].key;
	} else {
		if(longtime < now || longlen != keylen) {
			oldkey = longkey;
			longkey = make_temp_key(keylen);
			longtime = now + KEY_CACHE_TIME;
			longlen = keylen;
			if(oldkey)
				RSA_free(oldkey);
		}
		retval = longkey;
	}
	return retval;
}

static int	verify_cb(X509_STORE_CTX *x509, void *d)
{
	return 1;
}

static	SSL_CTX *ssl_init(char *certf, char *keyf)
{
	SSL_CTX *c;
	DH *dh;

	ERR_load_crypto_strings();
	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();

	c = SSL_CTX_new(SSLv23_server_method());
	SSL_CTX_set_quiet_shutdown(c, 1);
	SSL_CTX_set_options(c, SSL_OP_ALL);
#if SSLEAY_VERSION_NUMBER >= 0x00906000L
	SSL_CTX_set_mode(c, SSL_MODE_ENABLE_PARTIAL_WRITE);
#endif /* OpenSSL-0.9.6 */
/*	SSL_CTX_set_session_cache_mode(c, SSL_SESS_CACHE_OFF); */

	if ((SSL_CTX_use_certificate_file(c, certf,
	     SSL_FILETYPE_PEM) <= 0) ||
	    (SSL_CTX_use_PrivateKey_file(c, keyf,
	     SSL_FILETYPE_PEM) <= 0) ||
	    (!SSL_CTX_check_private_key(c))) {
		SSL_CTX_free(c);
		fprintf(stderr, "can't initialize ssl key/cert.\n");
		return NULL;
	}
        SSL_CTX_set_tmp_rsa_callback(c, tmp_rsa_cb);
	dh = get_dh512();
	SSL_CTX_set_tmp_dh(c, dh);
	DH_free(dh);

	SSL_CTX_set_verify(c, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_cert_verify_callback(c, verify_cb, NULL);
	return c;
}

/***********************************************
 * ircd cruft
 ***********************************************/
uint64_t now;
#define SET_READ(fd) { FD_SET(fd, &rfds); DEBUG("SET_READ(%d)", fd); }
#define SET_WRITE(fd) { FD_SET(fd, &wfds); DEBUG("SET_WRITE(%d)", fd); }
#define UNSET_READ(fd) { FD_CLR(fd, &rfds); FD_CLR(fd, &trfds); DEBUG("UNSET_READ(%d)",fd); }
#define UNSET_WRITE(fd) { FD_CLR(fd, &wfds); FD_CLR(fd, &twfds); DEBUG("UNSET_WRITE(%d)", fd); }

static fd_set rfds, wfds, trfds, twfds;
static SSL_CTX *sslctx;
static int maxfd=0;

#define MAXFD(f) { if (f>maxfd) maxfd=f; };

void	set_non_blocking(int fd)
{
	int	res, nonb = 0;

	MAXFD(fd);
#ifdef NBLOCK_POSIX
	nonb |= O_NONBLOCK;
#endif
#ifdef NBLOCK_BSD
	nonb |= O_NDELAY;
#endif
#ifdef NBLOCK_SYSV
	/* This portion of code might also apply to NeXT.  -LynX */
	res = 1;

	if (ioctl (fd, FIONBIO, &res) < 0)
		report_error("ioctl(fd,FIONBIO) failed ");
#else
	if ((res = fcntl(fd, F_GETFL, 0)) == -1)
		report_error("fcntl(fd, F_GETFL) failed for")
	else if (fcntl(fd, F_SETFL, res | nonb) == -1)
		report_error("fcntl(fd, F_SETL, nonb) failed for");
#endif
	return;
}


struct	client {
	uint64_t start;
	int	cfd; /* connection to client (ssl) */
	int	sfd; /* connection to server (plain) */
	SSL	*ssl;
	int	sbuff;
	int	sbufp;
	int	rbuff;
	int	rbufp;
	char	rbuf[BSIZE];
	char	sbuf[BSIZE];
};

static struct client *fdtab[FDSETSIZE];

void	kill_client(struct client *c)
{
	fdtab[c->sfd] = NULL;
	fdtab[c->cfd] = NULL;
	UNSET_READ(c->cfd); UNSET_WRITE(c->cfd);
	UNSET_READ(c->sfd); UNSET_WRITE(c->sfd);
	close(c->sfd);
	close(c->cfd);
	SSL_free(c->ssl);
	free(c);
}

void	client_add(struct client *c)
{
	c->ssl = SSL_new(sslctx);
	SSL_clear(c->ssl);
	if (!SSL_set_fd(c->ssl, c->cfd)) {
		SSL_free(c->ssl);
		close(c->cfd); close(c->sfd);
		free(c);
		return;
	}
	SSL_set_accept_state(c->ssl);
	FD_SET(c->cfd, &rfds);
	FD_SET(c->sfd, &rfds);
	fdtab[c->cfd] = c;
	fdtab[c->sfd] = c;
	c->rbuff = c->sbuff = BSIZE;
}

int accept_client()
{
	int sp[2];
	struct client *cl = malloc(sizeof(struct client));
	memset(cl, 0, sizeof(*cl));

	/* stdin is same descriptor across all workers; note that fdpassing is
	 * atomic, thus clients are distributed in round-robin fashion */
	cl->cfd = receive_fd(0); 
	if (cl->cfd < 0) return 0;
	MAXFD(cl->cfd);

	/* NOTE: pipe() is actually much more efficient here (pipes on modern
         * unix systems are bidirectional). However ircd uses send() everywhere
	 * (though there is no reason to do so) resulting ENOTSOCK. Separate patch
         * doing s/send/write/g needed. */
#if 0
	assert(!pipe(sp));
#else
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sp)>=0);
#endif
	set_non_blocking(sp[0]);
	set_non_blocking(sp[1]);

	/* while this might appear to be a race at first sight, it is not because
         * the control pipe on stdin is a blocking fd - ircd never does another
         * sendfd until it finishes receive_fd() triggered by the line below - everything
         * is serialized */
	send_fd(0, sp[1]);
	close(sp[1]);
	cl->sfd = sp[0];
	cl->start = now;

	client_add(cl);
	return 1;
}

void	do_handshake(struct client *c)
{
	char	info[1024];
	int	ret = SSL_accept(c->ssl);
	const SSL_CIPHER *ci;
	X509 *cert;
	char *p;
	int i;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int n;


	/* ssl will preemptively tell us */
	UNSET_WRITE(c->cfd);
	if (ret <= 0) switch (SSL_get_error(c->ssl, ret)) {
		case SSL_ERROR_NONE: break;
		case SSL_ERROR_WANT_WRITE: SET_WRITE(c->cfd); break;
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_SYSCALL:
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR) || (!errno))
				return;
			DEBUG("bad syscall errno %d", errsave);
		default:
			DEBUG("hs: client kill eof?");
			kill_client(c);
			return;
	}
	DEBUG("handshake fd %d\n", c->cfd);

	ci = SSL_get_current_cipher(c->ssl);
	p = c->sbuf;

	p += sprintf(p,
		"NOTICE AUTH :*** %s negotiation successful after %dms\r\n"
		"NOTICE AUTH :*** Session cipher is %s\r\n",
		SSL_CIPHER_get_version(ci),
		now - c->start,
		SSL_CIPHER_get_name(ci));
	if (cert = SSL_get_peer_certificate(c->ssl)) {
		X509_digest(cert, EVP_sha1(), md, &n);
		p += sprintf(p, "NOTICE AUTH :*** Your client cert SHA1 fingerprint: ");
		for (i = 0; i < n; i++) p += sprintf(p, "%02hhx", md[i]);
		p += sprintf(p, "\r\n");
	}
	DEBUG("intro size %d",(p-c->sbuf));
	assert((p-c->sbuf)<BSIZE);
	c->sbufp = p - c->sbuf;
	c->sbuff = BSIZE - c->sbufp;
	p = c->rbuf;
	/* This is currently ignored by ircd, but eventually,
         * we might use this stuff for things like /oper */
	p += sprintf(p, "TPROXY :%s%s", SSL_CIPHER_get_version(ci), cert?":":"");
	if (cert) for (i = 0; i < n; i++) p += sprintf(p, "%02hhx", md[i]);
	p += sprintf(p, "\r\n");
	c->rbufp = p - c->rbuf;
	c->rbuff = BSIZE - c->rbufp;

	DEBUG("handshake success");
	/* handshake done, incoming reads enable writes for counterparty */
	SET_READ(c->cfd);
	SET_READ(c->sfd);
	UNSET_WRITE(c->cfd);
	UNSET_WRITE(c->sfd);
}

void	process_read(int fd)
{
	int ret;
	struct client *c = fdtab[fd];
	assert(c->rbuff<=BSIZE);
	assert(c->sbuff<=BSIZE);

	if (!SSL_is_init_finished(c->ssl)) {
		do_handshake(c);
		return;
	}

	DEBUG("process read fd %d\n", fd);

	/* read from SSL client */
	if (c->cfd == fd) {
		ret = SSL_read(c->ssl, c->rbuf + c->rbufp, c->rbuff);
		if (ret > 0) {
			/* we will need to write this response to server */
			SET_WRITE(c->sfd);
			c->rbuff -= ret;
			c->rbufp += ret;
			/* if we have no room for further reads, disable reads from client */
			if (c->rbuff <= 0) UNSET_READ(c->cfd);
		}

		/* now figure out if SSL is ok */
		switch (SSL_get_error(c->ssl, ret)) {
			case SSL_ERROR_NONE: return;
			case SSL_ERROR_WANT_WRITE: SET_WRITE(c->cfd); break;
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_SYSCALL:
				if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR) || (!errno))
					return;
				DEBUG("read: bad syscall errno %d", errsave);
			default:
				DEBUG("read: client kill eof (%d)?", ret);
				kill_client(c);
				return;
		}
	}

	/* read from the server; if the handshake is not complete unset read notification */
	if (!SSL_is_init_finished(c->ssl)) {
		UNSET_READ(c->sfd);
		return;
	}

	/* server probably sent something to us */
	DEBUG("WR sbufp=%d,sbuff=%d",c->sbufp,c->sbuff);
	ret = read(c->sfd, c->sbuf + c->sbufp, c->sbuff);
	if (ret <= 0) {
		kill_client(c);
		return;
	}

	/* got data, enable writes on client, this continues later on in process_write() */
	SET_WRITE(c->cfd);
	c->sbufp += ret;
	c->sbuff -= ret;

	/* we have no more buffer space available, disable further reads from server */
	if (!c->sbuff) UNSET_READ(c->sfd);
}

void	process_write(int fd)
{
	int sent, ret;
	struct client *c = fdtab[fd];
	assert(c->rbuff<=BSIZE);
	assert(c->sbuff<=BSIZE);

	if (!SSL_is_init_finished(c->ssl)) {
		do_handshake(c);
		return;
	}

	/* we have data buffered to send to client */
	if ((c->cfd == fd) && (c->sbufp)) {
		sent = SSL_write(c->ssl, c->sbuf, c->sbufp);
		if (sent >= 0) {
			/* we will probably read some sort of response from server */
			memmove(c->sbuf, c->sbuf + sent, c->sbufp - sent);
			c->sbufp -= sent;
			c->sbuff += sent;
			/* re-enable potentially disabled reads from server (when c->sbuff was 0) */
			DEBUG("WR sbufp=%d,sbuff=%d",c->sbufp,c->sbuff);
			/* we have no more stuff to send to client, unset writes */
			if (!c->sbufp) UNSET_WRITE(c->cfd);
		}
		/* now figure out if SSL is ok */
		switch (ret = SSL_get_error(c->ssl, ret)) {
			case SSL_ERROR_NONE: break;
			case SSL_ERROR_WANT_WRITE:
				/* this happens when we disabled writes below */
				SET_WRITE(c->cfd);
				break;
			case SSL_ERROR_WANT_READ:
				/* we have data to write but ssl must read something first. */
				UNSET_WRITE(c->cfd);
				SET_READ(c->cfd);
			case SSL_ERROR_SYSCALL:
				if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR) || (!errno))
					break;
				DEBUG("bad syscall errno (%d)", errsave);
			default:
				DEBUG("write: client kill eof (%d)?", ret);
				kill_client(c);
				return;
		}
	}
	/* there is room made, enable server reads */
	if (c->sbuff) SET_READ(c->sfd);

	/* we have nothing buffered from client, disable writes, re-enable potentially disabled reads */
	if (!c->rbufp) {
		/* nothing to write to server socket, bail out */
		UNSET_WRITE(c->sfd);
		SET_READ(c->cfd);
		return;
	};

	/* flush buffer to server socket */
	sent = write(c->sfd, c->rbuf, c->rbufp);
	if (sent >= 0) {
		memmove(c->rbuf, c->rbuf + sent, c->rbufp - sent);
		c->rbufp -= sent;
		c->rbuff += sent;
		/* if rbufp is 0 now, this will iterate once more */
	}
}

int	run_server()
{
	int i;
	sslctx = ssl_init(TPROXY_CONF "/server.cert",TPROXY_CONF "/server.key");

	FD_SET(0, &rfds);
	while (1) {
		int got;
		struct timeval tv;
		memcpy(&trfds, &rfds, sizeof(rfds));
		memcpy(&twfds, &wfds, sizeof(wfds));
		got = select(maxfd+1, &trfds, &twfds, NULL, NULL);
		if (got < 0) return;
		gettimeofday(&tv, NULL);
		now = tv.tv_sec * 1000;
		now += tv.tv_usec / 1000;

		if (got < 0) return 0;

		if (FD_ISSET(0, &trfds))
			if (!accept_client()) return 0;

		for (i = 1; i < maxfd+1; i++) {
			if (FD_ISSET(i, &trfds))
				process_read(i);
			if (FD_ISSET(i, &twfds))
				process_write(i);
		}
	}
}

#endif
int	main()
{
#ifdef USE_TPROXY
	int	ncpu = (TPROXY_NCPU)-1; /* one cpu left for ircd */

	ncpu = ncpu<1?1:ncpu;

	/* start servers */
	while (ncpu-->1) if (!fork()) return run_server();
	return run_server();
#else
	return 0;
#endif
}


