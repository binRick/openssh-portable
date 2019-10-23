/* $OpenBSD: ssh-agent.c,v 1.237 2019/06/28 13:35:04 deraadt Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * The authentication agent program.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#ifdef HAVE_SYS_UN_H
# include <sys/un.h>
#endif
#include "openbsd-compat/sys-queue.h"

#ifdef WITH_OPENSSL
#include <openssl/evp.h>
#include "openbsd-compat/openssl-compat.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#ifdef HAVE_PATHS_H
# include <paths.h>
#endif
#ifdef HAVE_POLL_H
# include <poll.h>
#endif
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#ifdef HAVE_UTIL_H
# include <util.h>
#endif

#include "xmalloc.h"
#include "ssh.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "authfd.h"
#include "compat.h"
#include "log.h"
#include "misc.h"
#include "digest.h"
#include "ssherr.h"
#include "match.h"

#ifdef ENABLE_PKCS11
#include "ssh-pkcs11.h"
#endif

#ifndef DEFAULT_PKCS11_WHITELIST
# define DEFAULT_PKCS11_WHITELIST "/usr/lib*/*,/usr/local/lib*/*"
#endif

#include <sys/prctl.h>
#define PR_SET_PTRACER 0x59616d61
#define _LINUX_SOURCE_COMPAT
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>



/* Maximum accepted message length */
#define AGENT_MAX_LEN	(256*1024)
/* Maximum bytes to read from client socket */
#define AGENT_RBUF_LEN	(4096)

#include <jwt.h>

typedef enum {
	AUTH_UNUSED,
	AUTH_SOCKET,
	AUTH_CONNECTION
} sock_type;

typedef struct {
	int fd;
	sock_type type;
	struct sshbuf *input;
	struct sshbuf *output;
	struct sshbuf *request;
} SocketEntry;

u_int sockets_alloc = 0;
SocketEntry *sockets = NULL;

typedef struct identity {
	TAILQ_ENTRY(identity) next;
	struct sshkey *key;
	char *comment;
	char *provider;
	time_t death;
	u_int confirm;
} Identity;

struct idtable {
	int nentries;
	TAILQ_HEAD(idqueue, identity) idlist;
};

/* private key table */
struct idtable *idtab;

int max_fd = 0;

/* pid of shell == parent of agent */
pid_t parent_pid = -1;
time_t parent_alive_interval = 0;

/* pid of process for which cleanup_socket is applicable */
pid_t cleanup_pid = 0;

/* pathname and directory for AUTH_SOCKET */
char socket_name[PATH_MAX];
char socket_dir[PATH_MAX];

/* PKCS#11 path whitelist */
static char *pkcs11_whitelist;

/* locking */
#define LOCK_SIZE	32
#define LOCK_SALT_SIZE	16
#define LOCK_ROUNDS	1
int locked = 0;
u_char lock_pwhash[LOCK_SIZE];
u_char lock_salt[LOCK_SALT_SIZE];

extern char *__progname;

/* Default lifetime in seconds (0 == forever) */
static long lifetime = 0;

static int fingerprint_hash = SSH_FP_HASH_DEFAULT;

static void
close_socket(SocketEntry *e)
{
	close(e->fd);
	e->fd = -1;
	e->type = AUTH_UNUSED;
	sshbuf_free(e->input);
	sshbuf_free(e->output);
	sshbuf_free(e->request);
}

static void
idtab_init(void)
{
	idtab = xcalloc(1, sizeof(*idtab));
	TAILQ_INIT(&idtab->idlist);
	idtab->nentries = 0;
}

static void
free_identity(Identity *id)
{
	sshkey_free(id->key);
	free(id->provider);
	free(id->comment);
	free(id);
}

/* return matching private key for given public key */
static Identity *
lookup_identity(struct sshkey *key)
{
	Identity *id;

	TAILQ_FOREACH(id, &idtab->idlist, next) {
		if (sshkey_equal(key, id->key))
			return (id);
	}
	return (NULL);
}

/* Check confirmation of keysign request */
static int
confirm_key(Identity *id)
{
	char *p;
	int ret = -1;

	p = sshkey_fingerprint(id->key, fingerprint_hash, SSH_FP_DEFAULT);
	if (p != NULL &&
	    ask_permission("Allow use of key %s?\nKey fingerprint %s.",
	    id->comment, p))
		ret = 0;
	free(p);

	return (ret);
}

static void
send_status(SocketEntry *e, int success)
{
	int r;

	if ((r = sshbuf_put_u32(e->output, 1)) != 0 ||
	    (r = sshbuf_put_u8(e->output, success ?
	    SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
}

/* send list of supported public keys to 'client' */
static void
process_request_identities(SocketEntry *e)
{
	Identity *id;
	struct sshbuf *msg;
	int r;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_u8(msg, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(msg, idtab->nentries)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	TAILQ_FOREACH(id, &idtab->idlist, next) {
		if ((r = sshkey_puts_opts(id->key, msg, SSHKEY_SERIALIZE_INFO))
		     != 0 ||
		    (r = sshbuf_put_cstring(msg, id->comment)) != 0) {
			error("%s: put key/comment: %s", __func__,
			    ssh_err(r));
			continue;
		}
	}
	if ((r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	sshbuf_free(msg);
}


static char *
agent_decode_alg(struct sshkey *key, u_int flags)
{
	if (key->type == KEY_RSA) {
		if (flags & SSH_AGENT_RSA_SHA2_256)
			return "rsa-sha2-256";
		else if (flags & SSH_AGENT_RSA_SHA2_512)
			return "rsa-sha2-512";
	} else if (key->type == KEY_RSA_CERT) {
		if (flags & SSH_AGENT_RSA_SHA2_256)
			return "rsa-sha2-256-cert-v01@openssh.com";
		else if (flags & SSH_AGENT_RSA_SHA2_512)
			return "rsa-sha2-512-cert-v01@openssh.com";
	}
	return NULL;
}

/* ssh2 only */
static void
process_sign_request2(SocketEntry *e)
{
	const u_char *data;
	u_char *signature = NULL;
	size_t dlen, slen = 0;
	u_int compat = 0, flags;
	int r, ok = -1;
	struct sshbuf *msg;
	struct sshkey *key = NULL;
	struct identity *id;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshkey_froms(e->request, &key)) != 0 ||
	    (r = sshbuf_get_string_direct(e->request, &data, &dlen)) != 0 ||
	    (r = sshbuf_get_u32(e->request, &flags)) != 0) {
		error("%s: couldn't parse request: %s", __func__, ssh_err(r));
		goto send;
	}

	if ((id = lookup_identity(key)) == NULL) {
		verbose("%s: %s key not found", __func__, sshkey_type(key));
		goto send;
	}
	if (id->confirm && confirm_key(id) != 0) {
		verbose("%s: user refused key", __func__);
		goto send;
	}
	if ((r = sshkey_sign(id->key, &signature, &slen,
	    data, dlen, agent_decode_alg(key, flags), compat)) != 0) {
		error("%s: sshkey_sign: %s", __func__, ssh_err(r));
		goto send;
	}
	/* Success */
	ok = 0;
 send:
	sshkey_free(key);
	if (ok == 0) {
		if ((r = sshbuf_put_u8(msg, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(msg, signature, slen)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	} else if ((r = sshbuf_put_u8(msg, SSH_AGENT_FAILURE)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	if ((r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	sshbuf_free(msg);
	free(signature);
}

/* shared */
static void
process_remove_identity(SocketEntry *e)
{
	int r, success = 0;
	struct sshkey *key = NULL;
	Identity *id;

	if ((r = sshkey_froms(e->request, &key)) != 0) {
		error("%s: get key: %s", __func__, ssh_err(r));
		goto done;
	}
	if ((id = lookup_identity(key)) == NULL) {
		debug("%s: key not found", __func__);
		goto done;
	}
	/* We have this key, free it. */
	if (idtab->nentries < 1)
		fatal("%s: internal error: nentries %d",
		    __func__, idtab->nentries);
	TAILQ_REMOVE(&idtab->idlist, id, next);
	free_identity(id);
	idtab->nentries--;
	sshkey_free(key);
	success = 1;
 done:
	send_status(e, success);
}

static void
process_remove_all_identities(SocketEntry *e)
{
	Identity *id;

	/* Loop over all identities and clear the keys. */
	for (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, next);
		free_identity(id);
	}

	/* Mark that there are no identities. */
	idtab->nentries = 0;

	/* Send success. */
	send_status(e, 1);
}

/* removes expired keys and returns number of seconds until the next expiry */
static time_t
reaper(void)
{
	time_t deadline = 0, now = monotime();
	Identity *id, *nxt;

	for (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		if (id->death == 0)
			continue;
		if (now >= id->death) {
			debug("expiring key '%s'", id->comment);
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		} else
			deadline = (deadline == 0) ? id->death :
			    MINIMUM(deadline, id->death);
	}
	if (deadline == 0 || deadline <= now)
		return 0;
	else
		return (deadline - now);
}

static void
process_add_identity(SocketEntry *e)
{
	Identity *id;
	int success = 0, confirm = 0;
	u_int seconds, maxsign;
	char *comment = NULL;
	time_t death = 0;
	struct sshkey *k = NULL;
	u_char ctype;
	int r = SSH_ERR_INTERNAL_ERROR;

	if ((r = sshkey_private_deserialize(e->request, &k)) != 0 ||
	    k == NULL ||
	    (r = sshbuf_get_cstring(e->request, &comment, NULL)) != 0) {
		error("%s: decode private key: %s", __func__, ssh_err(r));
		goto err;
	}
	if ((r = sshkey_shield_private(k)) != 0) {
		error("%s: shield private key: %s", __func__, ssh_err(r));
		goto err;
	}
	while (sshbuf_len(e->request)) {
		if ((r = sshbuf_get_u8(e->request, &ctype)) != 0) {
			error("%s: buffer error: %s", __func__, ssh_err(r));
			goto err;
		}
		switch (ctype) {
		case SSH_AGENT_CONSTRAIN_LIFETIME:
			if ((r = sshbuf_get_u32(e->request, &seconds)) != 0) {
				error("%s: bad lifetime constraint: %s",
				    __func__, ssh_err(r));
				goto err;
			}
			death = monotime() + seconds;
			break;
		case SSH_AGENT_CONSTRAIN_CONFIRM:
			confirm = 1;
			break;
		case SSH_AGENT_CONSTRAIN_MAXSIGN:
			if ((r = sshbuf_get_u32(e->request, &maxsign)) != 0) {
				error("%s: bad maxsign constraint: %s",
				    __func__, ssh_err(r));
				goto err;
			}
			if ((r = sshkey_enable_maxsign(k, maxsign)) != 0) {
				error("%s: cannot enable maxsign: %s",
				    __func__, ssh_err(r));
				goto err;
			}
			break;
		default:
			error("%s: Unknown constraint %d", __func__, ctype);
 err:
			sshbuf_reset(e->request);
			free(comment);
			sshkey_free(k);
			goto send;
		}
	}

	success = 1;
	if (lifetime && !death)
		death = monotime() + lifetime;
	if ((id = lookup_identity(k)) == NULL) {
		id = xcalloc(1, sizeof(Identity));
		TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
		/* Increment the number of identities. */
		idtab->nentries++;
	} else {
		/* key state might have been updated */
		sshkey_free(id->key);
		free(id->comment);
	}
	id->key = k;
	id->comment = comment;
	id->death = death;
	id->confirm = confirm;
send:
	send_status(e, success);
}

/* XXX todo: encrypt sensitive data with passphrase */
static void
process_lock_agent(SocketEntry *e, int lock)
{
	int r, success = 0, delay;
	char *passwd;
	u_char passwdhash[LOCK_SIZE];
	static u_int fail_count = 0;
	size_t pwlen;

	/*
	 * This is deliberately fatal: the user has requested that we lock,
	 * but we can't parse their request properly. The only safe thing to
	 * do is abort.
	 */
	if ((r = sshbuf_get_cstring(e->request, &passwd, &pwlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (pwlen == 0) {
		debug("empty password not supported");
	} else if (locked && !lock) {
		if (bcrypt_pbkdf(passwd, pwlen, lock_salt, sizeof(lock_salt),
		    passwdhash, sizeof(passwdhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		if (timingsafe_bcmp(passwdhash, lock_pwhash, LOCK_SIZE) == 0) {
			debug("agent unlocked");
			locked = 0;
			fail_count = 0;
			explicit_bzero(lock_pwhash, sizeof(lock_pwhash));
			success = 1;
		} else {
			/* delay in 0.1s increments up to 10s */
			if (fail_count < 100)
				fail_count++;
			delay = 100000 * fail_count;
			debug("unlock failed, delaying %0.1lf seconds",
			    (double)delay/1000000);
			usleep(delay);
		}
		explicit_bzero(passwdhash, sizeof(passwdhash));
	} else if (!locked && lock) {
		debug("agent locked");
		locked = 1;
		arc4random_buf(lock_salt, sizeof(lock_salt));
		if (bcrypt_pbkdf(passwd, pwlen, lock_salt, sizeof(lock_salt),
		    lock_pwhash, sizeof(lock_pwhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		success = 1;
	}
	explicit_bzero(passwd, pwlen);
	free(passwd);
	send_status(e, success);
}

static void
no_identities(SocketEntry *e)
{
	struct sshbuf *msg;
	int r;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_u8(msg, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(msg, 0)) != 0 ||
	    (r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	sshbuf_free(msg);
}

#ifdef ENABLE_PKCS11
static void
process_add_smartcard_key(SocketEntry *e)
{
	char *provider = NULL, *pin = NULL, canonical_provider[PATH_MAX];
	int r, i, count = 0, success = 0, confirm = 0;
	u_int seconds;
	time_t death = 0;
	u_char type;
	struct sshkey **keys = NULL, *k;
	Identity *id;

	if ((r = sshbuf_get_cstring(e->request, &provider, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, NULL)) != 0) {
		error("%s: buffer error: %s", __func__, ssh_err(r));
		goto send;
	}

	while (sshbuf_len(e->request)) {
		if ((r = sshbuf_get_u8(e->request, &type)) != 0) {
			error("%s: buffer error: %s", __func__, ssh_err(r));
			goto send;
		}
		switch (type) {
		case SSH_AGENT_CONSTRAIN_LIFETIME:
			if ((r = sshbuf_get_u32(e->request, &seconds)) != 0) {
				error("%s: buffer error: %s",
				    __func__, ssh_err(r));
				goto send;
			}
			death = monotime() + seconds;
			break;
		case SSH_AGENT_CONSTRAIN_CONFIRM:
			confirm = 1;
			break;
		default:
			error("%s: Unknown constraint type %d", __func__, type);
			goto send;
		}
	}
	if (realpath(provider, canonical_provider) == NULL) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		goto send;
	}
	if (match_pattern_list(canonical_provider, pkcs11_whitelist, 0) != 1) {
		verbose("refusing PKCS#11 add of \"%.100s\": "
		    "provider not whitelisted", canonical_provider);
		goto send;
	}
	debug("%s: add %.100s", __func__, canonical_provider);
	if (lifetime && !death)
		death = monotime() + lifetime;

	count = pkcs11_add_provider(canonical_provider, pin, &keys);
	for (i = 0; i < count; i++) {
		k = keys[i];
		if (lookup_identity(k) == NULL) {
			id = xcalloc(1, sizeof(Identity));
			id->key = k;
			id->provider = xstrdup(canonical_provider);
			id->comment = xstrdup(canonical_provider); /* XXX */
			id->death = death;
			id->confirm = confirm;
			TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
			idtab->nentries++;
			success = 1;
		} else {
			sshkey_free(k);
		}
		keys[i] = NULL;
	}
send:
	free(pin);
	free(provider);
	free(keys);
	send_status(e, success);
}

static void
process_remove_smartcard_key(SocketEntry *e)
{
	char *provider = NULL, *pin = NULL, canonical_provider[PATH_MAX];
	int r, success = 0;
	Identity *id, *nxt;

	if ((r = sshbuf_get_cstring(e->request, &provider, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, NULL)) != 0) {
		error("%s: buffer error: %s", __func__, ssh_err(r));
		goto send;
	}
	free(pin);

	if (realpath(provider, canonical_provider) == NULL) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		goto send;
	}

	debug("%s: remove %.100s", __func__, canonical_provider);
	for (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		/* Skip file--based keys */
		if (id->provider == NULL)
			continue;
		if (!strcmp(canonical_provider, id->provider)) {
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		}
	}
	if (pkcs11_del_provider(canonical_provider) == 0)
		success = 1;
	else
		error("%s: pkcs11_del_provider failed", __func__);
send:
	free(provider);
	send_status(e, success);
}
#endif /* ENABLE_PKCS11 */

/* dispatch incoming messages */

static int
process_message(u_int socknum)
{
	u_int msg_len;
	u_char type;
	const u_char *cp;
	int r;
	SocketEntry *e;

	if (socknum >= sockets_alloc) {
		fatal("%s: socket number %u >= allocated %u",
		    __func__, socknum, sockets_alloc);
	}
	e = &sockets[socknum];

	if (sshbuf_len(e->input) < 5)
		return 0;		/* Incomplete message header. */
	cp = sshbuf_ptr(e->input);
	msg_len = PEEK_U32(cp);
	if (msg_len > AGENT_MAX_LEN) {
		debug("%s: socket %u (fd=%d) message too long %u > %u",
		    __func__, socknum, e->fd, msg_len, AGENT_MAX_LEN);
		return -1;
	}
	if (sshbuf_len(e->input) < msg_len + 4)
		return 0;		/* Incomplete message body. */

	/* move the current input to e->request */
	sshbuf_reset(e->request);
	if ((r = sshbuf_get_stringb(e->input, e->request)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &type)) != 0) {
		if (r == SSH_ERR_MESSAGE_INCOMPLETE ||
		    r == SSH_ERR_STRING_TOO_LARGE) {
			debug("%s: buffer error: %s", __func__, ssh_err(r));
			return -1;
		}
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}

	debug("%s: socket %u (fd=%d) type %d", __func__, socknum, e->fd, type);

	/* check whether agent is locked */
	if (locked && type != SSH_AGENTC_UNLOCK) {
		sshbuf_reset(e->request);
		switch (type) {
		case SSH2_AGENTC_REQUEST_IDENTITIES:
			/* send empty lists */
			no_identities(e);
			break;
		default:
			/* send a fail message for all other request types */
			send_status(e, 0);
		}
		return 0;
	}

	switch (type) {
	case SSH_AGENTC_LOCK:
	case SSH_AGENTC_UNLOCK:
		process_lock_agent(e, type == SSH_AGENTC_LOCK);
		break;
	case SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
		process_remove_all_identities(e); /* safe for !WITH_SSH1 */
		break;
	/* ssh2 */
	case SSH2_AGENTC_SIGN_REQUEST:
		process_sign_request2(e);
		break;
	case SSH2_AGENTC_REQUEST_IDENTITIES:
		process_request_identities(e);
		break;
	case SSH2_AGENTC_ADD_IDENTITY:
	case SSH2_AGENTC_ADD_ID_CONSTRAINED:
		process_add_identity(e);
		break;
	case SSH2_AGENTC_REMOVE_IDENTITY:
		process_remove_identity(e);
		break;
	case SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		process_remove_all_identities(e);
		break;
#ifdef ENABLE_PKCS11
	case SSH_AGENTC_ADD_SMARTCARD_KEY:
	case SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED:
		process_add_smartcard_key(e);
		break;
	case SSH_AGENTC_REMOVE_SMARTCARD_KEY:
		process_remove_smartcard_key(e);
		break;
#endif /* ENABLE_PKCS11 */
	default:
		/* Unknown message.  Respond with failure. */
		error("Unknown message %d", type);
		sshbuf_reset(e->request);
		send_status(e, 0);
		break;
	}
	return 0;
}

static void
new_socket(sock_type type, int fd)
{


	u_int i, old_alloc, new_alloc;

	set_nonblock(fd);

	if (fd > max_fd)
		max_fd = fd;

	for (i = 0; i < sockets_alloc; i++)
		if (sockets[i].type == AUTH_UNUSED) {
			sockets[i].fd = fd;
			if ((sockets[i].input = sshbuf_new()) == NULL)
				fatal("%s: sshbuf_new failed", __func__);
			if ((sockets[i].output = sshbuf_new()) == NULL)
				fatal("%s: sshbuf_new failed", __func__);
			if ((sockets[i].request = sshbuf_new()) == NULL)
				fatal("%s: sshbuf_new failed", __func__);
			sockets[i].type = type;
			return;
		}
	old_alloc = sockets_alloc;
	new_alloc = sockets_alloc + 10;
	sockets = xreallocarray(sockets, new_alloc, sizeof(sockets[0]));
	for (i = old_alloc; i < new_alloc; i++)
		sockets[i].type = AUTH_UNUSED;
	sockets_alloc = new_alloc;
	sockets[old_alloc].fd = fd;
	if ((sockets[old_alloc].input = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((sockets[old_alloc].output = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((sockets[old_alloc].request = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	sockets[old_alloc].type = type;
}

#if !defined(PT_ATTACHEXC) /* New replacement for PT_ATTACH */
   #if !defined(PTRACE_ATTACH) && defined(PT_ATTACH)
       #define PT_ATTACHEXC    PT_ATTACH
   #elif defined(PTRACE_ATTACH)
       #define PT_ATTACHEXC PTRACE_ATTACH
   #endif
#endif


void untraceable(){
   char proc[80];
   int pid, mine;
   switch(pid = fork()) {
   case  0:
       pid = getppid();
       sprintf(proc, "/proc/%d/as", (int)pid);
       close(0);
       mine = !open(proc, O_RDWR|O_EXCL);
       if (!mine && errno != EBUSY)
           mine = !ptrace(PT_ATTACHEXC, pid, 0, 0);
       if (mine) {
           kill(pid, SIGCONT);
       } else {
           fprintf(stderr, "%d is being traced!\n", (int)pid);
           kill(pid, SIGKILL);
       }
       _exit(mine);
   case -1:
       break;
   default:
       if (pid == waitpid(pid, 0, 0))
           return;
   }
   _exit(1);
}


char * readProcessEnvironmentToken(int PID, char * name_){
    char READ_PID_ENV_CMD[256];
    char *AUTH_TOKEN;
    sprintf(READ_PID_ENV_CMD, "cat /proc/%ld/environ|tr '\\000' '\\n'|grep '%s='", PID, name_);
    FILE *cmd=popen(READ_PID_ENV_CMD, "r");
    char result[5000]={0x0};
    while (fgets(result, sizeof(result), cmd) !=NULL){
           AUTH_TOKEN = strtok(result, "="); 
           if(AUTH_TOKEN == NULL){ 
                pclose(cmd);
                printf("[ssh-agent server] FAILED :: \"%s\" not found in client pid %ld environment\n", name_, PID);
                return 1;
           }
           AUTH_TOKEN = strtok(NULL, "="); 
    }
    pclose(cmd);
    return AUTH_TOKEN;
}

static int VALIDATE_ENVIRONMENT_TOKEN(long PID, char * name_){
    char *PUBLIC_KEY_ENCODED;
    char PID_ENV_PATH[256];
    char READ_PID_ENV_CMD[256];
    char *PUBLIC_KEY_DECODED, *VALID_ISSUER_ENCODED, *VALID_ISSUER_DECODED, *TOKEN_ISSUER;
    char *AUTH_TOKEN;
    char LOCAL_HOSTNAME[128];
    int PUBLIC_KEY_ENCODED_LENGTH, PUBLIC_KEY_DECODED_LENGTH, AUTH_TOKEN_LENGTH, VALID_ISSUER_DECODED_LENGTH, VALID_ISSUER_ENCODED_LENGTH;
    int VALID_ISSUER_DECODE_RESULT, AUTH_TOKEN_DECODE_RESULT, PUBLIC_KEY_DECODE_RESULT;
    jwt_t *AUTH_TOKEN_JWT_OBJECT;
    time_t now;
    time_t exp;
    time_t TOKEN_EXPIRES_TIMESTAMP, CURRENT_TIMESTAMP;
    int VALIDATIONS_EXPIRED = 1, VALIDATIONS_ISSUER = 1, EXPIRES_SECONDS_REMAINING = 0;
	size_t len;
    CURRENT_TIMESTAMP = time(NULL);


    ////////////////////////////////
    //     Get Local Hostname     //
    ////////////////////////////////
    gethostname(LOCAL_HOSTNAME, sizeof(LOCAL_HOSTNAME));
    printf("[ssh-agent server] LOCAL_HOSTNAME (%d bytes): %s\n", (int)strlen(LOCAL_HOSTNAME), LOCAL_HOSTNAME);


    ////////////////////////////////
    //     Get Valid Issuer       //
    ////////////////////////////////
    VALID_ISSUER_ENCODED = getenv("ISSUER");
    if(VALID_ISSUER_ENCODED == NULL){
        printf("[ssh-agent server] FAILED :: ISSUER env var not found\n");
        return 1;
    }
    printf("[ssh-agent server] VALID_ISSUER_ENCODED (%d bytes): %s\n", strlen(VALID_ISSUER_ENCODED), VALID_ISSUER_ENCODED);
    VALID_ISSUER_ENCODED_LENGTH = (int)strlen(VALID_ISSUER_ENCODED);
    VALID_ISSUER_DECODED = alloca(VALID_ISSUER_ENCODED_LENGTH * 2);
    VALID_ISSUER_DECODE_RESULT = jwt_Base64decode(VALID_ISSUER_DECODED, VALID_ISSUER_ENCODED);
    VALID_ISSUER_DECODED_LENGTH = (int)strlen(VALID_ISSUER_DECODED);
    printf("[ssh-agent server] VALID_ISSUER_DECODED (%d bytes): %s\n", VALID_ISSUER_DECODED_LENGTH, VALID_ISSUER_DECODED);


    ////////////////////////////////
    //     Get Valid Public Key   //
    ////////////////////////////////
    PUBLIC_KEY_ENCODED = getenv("PUBLIC_KEY");
    if(PUBLIC_KEY_ENCODED == NULL){
        printf("[ssh-agent server] FAILED :: PUBLIC_KEY env var not found\n");
        return 1;
    }
    PUBLIC_KEY_ENCODED_LENGTH = (int)strlen(PUBLIC_KEY_ENCODED);
    if(PUBLIC_KEY_ENCODED_LENGTH < 32){
        printf("[ssh-agent server] FAILED :: PUBLIC_KEY env var not valid (%d bytes)\n", PUBLIC_KEY_ENCODED_LENGTH);
        return 1;
    }
    printf("[ssh-agent server] PUBLIC_KEY_ENCODED (%d bytes): %s\n", PUBLIC_KEY_ENCODED_LENGTH, PUBLIC_KEY_ENCODED);


    ////////////////////////////////
    //  Decode Valid Public Key   //
    ////////////////////////////////
    PUBLIC_KEY_DECODED = alloca(PUBLIC_KEY_ENCODED_LENGTH * 2);
    PUBLIC_KEY_DECODE_RESULT = jwt_Base64decode(PUBLIC_KEY_DECODED, PUBLIC_KEY_ENCODED);
    PUBLIC_KEY_DECODED_LENGTH = (int)strlen(PUBLIC_KEY_DECODED);
    if(PUBLIC_KEY_DECODED_LENGTH < 32){
        printf("[ssh-agent server] FAILED :: Decoded PUBLIC_KEY not value (%d bytes)\n", PUBLIC_KEY_DECODED_LENGTH);
        return 1;
    }
    printf("[ssh-agent server] PUBLIC_KEY_DECODED (%d bytes): %s\n", PUBLIC_KEY_DECODED_LENGTH, PUBLIC_KEY_DECODED);


    ////////////////////////////////
    //  Read Client Process Env   //
    ////////////////////////////////
    sprintf(PID_ENV_PATH, "/proc/%ld/environ", PID);
    printf("[ssh-agent server] Validating PID=%ld PID_ENV_PATH=%s\n", PID, PID_ENV_PATH);


    AUTH_TOKEN = readProcessEnvironmentToken(PID, name_);
    if(AUTH_TOKEN == NULL){ 
        printf("[ssh-agent server] FAILED :: \"%s\" value not found in client pid %ld environment\n", name_, PID);
        return 1;
    }
    AUTH_TOKEN_LENGTH = (int)strlen(AUTH_TOKEN);
    if(AUTH_TOKEN_LENGTH < 32){
        printf("[ssh-agent server] FAILED :: \"%s\" valid value not found in client pid %ld environment (found %ld byte string)\n", name_, PID, AUTH_TOKEN_LENGTH);
        return 1;
    }

    printf("[ssh-agent-server] AUTH_TOKEN (%d bytes): %s\n", AUTH_TOKEN_LENGTH, AUTH_TOKEN); 
    

    ////////////////////////////////
    //  Validate Client Token     //
    ////////////////////////////////
    AUTH_TOKEN_DECODE_RESULT = jwt_decode(&AUTH_TOKEN_JWT_OBJECT, AUTH_TOKEN, PUBLIC_KEY_DECODED, strlen(PUBLIC_KEY_DECODED));
    printf("[ssh-agent server] AUTH_TOKEN_DECODE_RESULT=%d\n", AUTH_TOKEN_DECODE_RESULT);
    if(AUTH_TOKEN_DECODE_RESULT!=0){
        printf("\n\n[ssh-agent server] INVALID TOKEN\n\n");
        return AUTH_TOKEN_DECODE_RESULT;
    }

    ////////////////////////////////
    //  Extract Token Data        //
    ////////////////////////////////
    TOKEN_ISSUER = jwt_get_grant(AUTH_TOKEN_JWT_OBJECT, "iss");
    TOKEN_EXPIRES_TIMESTAMP = (time_t)jwt_get_grant_int(AUTH_TOKEN_JWT_OBJECT, "exp");

    ////////////////////////////////
    //  Calculate Validations     //
    ////////////////////////////////
    VALIDATIONS_EXPIRED = (TOKEN_EXPIRES_TIMESTAMP < CURRENT_TIMESTAMP);
    VALIDATIONS_ISSUER = (strcmp(VALID_ISSUER_DECODED, TOKEN_ISSUER) != 0);
    EXPIRES_SECONDS_REMAINING = TOKEN_EXPIRES_TIMESTAMP - CURRENT_TIMESTAMP;

    ////////////////////////////////
    //    Debug   Summary         //
    ////////////////////////////////
    printf("  TYP=%s\n", jwt_get_header(AUTH_TOKEN_JWT_OBJECT, "typ")); 
    printf("  ALG=%s\n", jwt_get_header(AUTH_TOKEN_JWT_OBJECT, "alg")); 
    printf("  serverid=%d\n", jwt_get_header_int(AUTH_TOKEN_JWT_OBJECT, "serverid")); 
    printf("  iat=%d\n", jwt_get_header_int(AUTH_TOKEN_JWT_OBJECT, "iat")); 
    printf("  jti=%d\n", jwt_get_header_int(AUTH_TOKEN_JWT_OBJECT, "jti")); 
    printf("  sub=%s\n", jwt_get_grant(AUTH_TOKEN_JWT_OBJECT, "sub")); 
    printf("  aud=%s\n", jwt_get_grant(AUTH_TOKEN_JWT_OBJECT, "aud")); 
    printf("  iss=%s\n", jwt_get_grant(AUTH_TOKEN_JWT_OBJECT, "iss")); 
    printf("  exp=%d\n", jwt_get_grant_int(AUTH_TOKEN_JWT_OBJECT, "exp")); 
    printf("  scope=%s\n", jwt_get_grants_json(AUTH_TOKEN_JWT_OBJECT, "scope"));
    printf("  dat=%s\n", jwt_get_grants_json(AUTH_TOKEN_JWT_OBJECT, "dat"));
    printf("  VALID_ISSUER_DECODED=%s\n", VALID_ISSUER_DECODED);
    printf("  TOKEN_ISSUER=%s\n", TOKEN_ISSUER);
    printf("  TOKEN_EXPIRES_TIMESTAMP=%d\n", TOKEN_EXPIRES_TIMESTAMP);
    printf("  CURRENT_TIMESTAMP=%d\n", CURRENT_TIMESTAMP);
    printf("  EXPIRES_SECONDS_REMAINING=%d\n", EXPIRES_SECONDS_REMAINING);

    ////////////////////////////////
    //   Validation   Summary     //
    ////////////////////////////////
    printf("\n[ssh-agent server] SUMMARY\n");
    printf("  VALIDATIONS_EXPIRED=%d\n", VALIDATIONS_EXPIRED);
    printf("  VALIDATIONS_ISSUER=%d\n", VALIDATIONS_ISSUER);

    int TOKEN_IS_VALID = 1;
    if(   VALIDATIONS_EXPIRED == 0 && VALIDATIONS_ISSUER  == 0 ){
        TOKEN_IS_VALID = 0;
        printf("\n\n[ssh-agent server] VALID TOKEN\n\n");
    }else{
        printf("\n\n[ssh-agent server] INVALID TOKEN\n\n");
    }
    return TOKEN_IS_VALID;

}

static int
handle_socket_read(u_int socknum)
{

	struct sockaddr_un sunaddr;
	socklen_t slen;
	uid_t euid;
	gid_t egid;
	int fd;

	slen = sizeof(sunaddr);
	fd = accept(sockets[socknum].fd, (struct sockaddr *)&sunaddr, &slen);
	if (fd == -1) {
		error("accept from AUTH_SOCKET: %s", strerror(errno));
		return -1;
	}
	if (getpeereid(fd, &euid, &egid) == -1) {
		error("getpeereid %d failed: %s", fd, strerror(errno));
		close(fd);
		return -1;
	}
    debug("%s: socket %u (fd=%d) euid=%d, egid=%d",
            __func__, socknum, fd, euid, egid);

    int len;
    struct ucred ucred;
    len = sizeof(struct ucred);

    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len) == -1) {
        debug("%s: getsockopt failed",__func__);
    }
    debug("Credentials from SO_PEERCRED: pid=%ld, euid=%ld, egid=%ld\n",(long) ucred.pid, (long) ucred.uid, (long) ucred.gid);

    if(VALIDATE_ENVIRONMENT_TOKEN(ucred.pid, "AUTH_TOKEN") != 0){
        error("Invalid Token from PID %ld", (long)ucred.pid);
        close(fd);
        return -1;
    }    

	if ((euid != 0) && (getuid() != euid)) {
		error("uid mismatch: peer euid %u != uid %u",
		    (u_int) euid, (u_int) getuid());
		close(fd);
		return -1;
	}
	new_socket(AUTH_CONNECTION, fd);
	return 0;
}

static int
handle_conn_read(u_int socknum)
{
	char buf[AGENT_RBUF_LEN];
	ssize_t len;
	int r;

	if ((len = read(sockets[socknum].fd, buf, sizeof(buf))) <= 0) {
		if (len == -1) {
			if (errno == EAGAIN || errno == EINTR)
				return 0;
			error("%s: read error on socket %u (fd %d): %s",
			    __func__, socknum, sockets[socknum].fd,
			    strerror(errno));
		}
		return -1;
	}
	if ((r = sshbuf_put(sockets[socknum].input, buf, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	explicit_bzero(buf, sizeof(buf));
	process_message(socknum);
	return 0;
}

static int
handle_conn_write(u_int socknum)
{
	ssize_t len;
	int r;

	if (sshbuf_len(sockets[socknum].output) == 0)
		return 0; /* shouldn't happen */
	if ((len = write(sockets[socknum].fd,
	    sshbuf_ptr(sockets[socknum].output),
	    sshbuf_len(sockets[socknum].output))) <= 0) {
		if (len == -1) {
			if (errno == EAGAIN || errno == EINTR)
				return 0;
			error("%s: read error on socket %u (fd %d): %s",
			    __func__, socknum, sockets[socknum].fd,
			    strerror(errno));
		}
		return -1;
	}
	if ((r = sshbuf_consume(sockets[socknum].output, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	return 0;
}

static void
after_poll(struct pollfd *pfd, size_t npfd, u_int maxfds)
{
	size_t i;
	u_int socknum, activefds = npfd;

	for (i = 0; i < npfd; i++) {
		if (pfd[i].revents == 0)
			continue;
		/* Find sockets entry */
		for (socknum = 0; socknum < sockets_alloc; socknum++) {
			if (sockets[socknum].type != AUTH_SOCKET &&
			    sockets[socknum].type != AUTH_CONNECTION)
				continue;
			if (pfd[i].fd == sockets[socknum].fd)
				break;
		}
		if (socknum >= sockets_alloc) {
			error("%s: no socket for fd %d", __func__, pfd[i].fd);
			continue;
		}
		/* Process events */
        //untraceable();
		switch (sockets[socknum].type) {
		case AUTH_SOCKET:
			if ((pfd[i].revents & (POLLIN|POLLERR)) == 0)
				break;
			if (npfd > maxfds) {
				debug3("out of fds (active %u >= limit %u); "
				    "skipping accept", activefds, maxfds);
				break;
			}
			if (handle_socket_read(socknum) == 0)
				activefds++;
			break;
		case AUTH_CONNECTION:
			if ((pfd[i].revents & (POLLIN|POLLERR)) != 0 &&
			    handle_conn_read(socknum) != 0) {
				goto close_sock;
			}
			if ((pfd[i].revents & (POLLOUT|POLLHUP)) != 0 &&
			    handle_conn_write(socknum) != 0) {
 close_sock:
				if (activefds == 0)
					fatal("activefds == 0 at close_sock");
				close_socket(&sockets[socknum]);
				activefds--;
				break;
			}
			break;
		default:
			break;
		}
	}
}



static int
prepare_poll(struct pollfd **pfdp, size_t *npfdp, int *timeoutp, u_int maxfds)
{
	struct pollfd *pfd = *pfdp;
	size_t i, j, npfd = 0;
	time_t deadline;
	int r;

	/* Count active sockets */
	for (i = 0; i < sockets_alloc; i++) {
		switch (sockets[i].type) {
		case AUTH_SOCKET:
		case AUTH_CONNECTION:
			npfd++;
			break;
		case AUTH_UNUSED:
			break;
		default:
			fatal("Unknown socket type %d", sockets[i].type);
			break;
		}
	}
	if (npfd != *npfdp &&
	    (pfd = recallocarray(pfd, *npfdp, npfd, sizeof(*pfd))) == NULL)
		fatal("%s: recallocarray failed", __func__);
	*pfdp = pfd;
	*npfdp = npfd;

	for (i = j = 0; i < sockets_alloc; i++) {
		switch (sockets[i].type) {
		case AUTH_SOCKET:
			if (npfd > maxfds) {
				debug3("out of fds (active %zu >= limit %u); "
				    "skipping arming listener", npfd, maxfds);
				break;
			}
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			pfd[j].events = POLLIN;
			j++;
			break;
		case AUTH_CONNECTION:
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			/*
			 * Only prepare to read if we can handle a full-size
			 * input read buffer and enqueue a max size reply..
			 */
			if ((r = sshbuf_check_reserve(sockets[i].input,
			    AGENT_RBUF_LEN)) == 0 &&
			    (r = sshbuf_check_reserve(sockets[i].output,
			     AGENT_MAX_LEN)) == 0)
				pfd[j].events = POLLIN;
			else if (r != SSH_ERR_NO_BUFFER_SPACE) {
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			}
			if (sshbuf_len(sockets[i].output) > 0)
				pfd[j].events |= POLLOUT;
			j++;
			break;
		default:
			break;
		}
	}
	deadline = reaper();
	if (parent_alive_interval != 0)
		deadline = (deadline == 0) ? parent_alive_interval :
		    MINIMUM(deadline, parent_alive_interval);
	if (deadline == 0) {
		*timeoutp = -1; /* INFTIM */
	} else {
		if (deadline > INT_MAX / 1000)
			*timeoutp = INT_MAX / 1000;
		else
			*timeoutp = deadline * 1000;
	}
	return (1);
}

static void
cleanup_socket(void)
{
	if (cleanup_pid != 0 && getpid() != cleanup_pid)
		return;
	debug("%s: cleanup", __func__);
	if (socket_name[0])
		unlink(socket_name);
	if (socket_dir[0])
		rmdir(socket_dir);
}

void
cleanup_exit(int i)
{
	cleanup_socket();
	_exit(i);
}

/*ARGSUSED*/
static void
cleanup_handler(int sig)
{
	cleanup_socket();
#ifdef ENABLE_PKCS11
	pkcs11_terminate();
#endif
	_exit(2);
}

static void
check_parent_exists(void)
{
	/*
	 * If our parent has exited then getppid() will return (pid_t)1,
	 * so testing for that should be safe.
	 */
	if (parent_pid != -1 && getppid() != parent_pid) {
		/* printf("Parent has died - Authentication agent exiting.\n"); */
		cleanup_socket();
		_exit(2);
	}
}

static void
usage(void)
{
	fprintf(stderr,"\n");
	exit(1);
}
static void
original_usage(void)
{
	fprintf(stderr,
	    "usage: ssh-agent [-c | -s] [-Dd] [-a bind_address] [-E fingerprint_hash]\n"
	    "                 [-P pkcs11_whitelist] [-t life] [command [arg ...]]\n"
	    "       ssh-agent [-c | -s] -k\n");
	exit(1);
}

int
main(int ac, char **av)
{
	int c_flag = 0, d_flag = 0, D_flag = 0, k_flag = 0, s_flag = 0;
	int sock, fd, ch, result, saved_errno;
	char *shell, *format, *pidstr, *agentsocket = NULL;
#ifdef HAVE_SETRLIMIT
	struct rlimit rlim;
#endif
	extern int optind;
	extern char *optarg;
	pid_t pid;
	char pidstrbuf[1 + 3 * sizeof pid];
	size_t len;
	mode_t prev_mask;
	int timeout = -1; /* INFTIM */
	struct pollfd *pfd = NULL;
	size_t npfd = 0;
	u_int maxfds;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* drop */
	setegid(getgid());
	setgid(getgid());


    untraceable();
	platform_disable_tracing(0);	/* strict=no */

	if (getrlimit(RLIMIT_NOFILE, &rlim) == -1)
		fatal("%s: getrlimit: %s", __progname, strerror(errno));

	__progname = ssh_get_progname(av[0]);
	seed_rng();

	char *FOREGROUND_MODE, *DEBUG_MODE = NULL;
	FOREGROUND_MODE = getenv("FOREGROUND_MODE");
	if ( (FOREGROUND_MODE != NULL) && ((len = strlen(FOREGROUND_MODE)) == 1)){
		if (d_flag || D_flag)
			usage();
		d_flag++;
    }
	DEBUG_MODE = getenv("DEBUG_MODE");
	if ( (DEBUG_MODE != NULL) && ((len = strlen(DEBUG_MODE)) == 1)){
		if (d_flag || D_flag)
			usage();
		D_flag++;
    }

	while ((ch = getopt(ac, av, "cDdksE:a:P:t:")) != -1) {
		switch (ch) {
		case 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			if (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			break;
		case 'c':
			if (s_flag)
				usage();
			c_flag++;
			break;
		case 'k':
			k_flag++;
			break;
		case 'P':
			if (pkcs11_whitelist != NULL)
				fatal("-P option already specified");
			pkcs11_whitelist = xstrdup(optarg);
			break;
		case 's':
			if (c_flag)
				usage();
			s_flag++;
			break;
		case 'd':
			if (d_flag || D_flag)
				usage();
			d_flag++;
			break;
		case 'D':
			if (d_flag || D_flag)
				usage();
			D_flag++;
			break;
		case 'a':
			agentsocket = optarg;
			break;
		case 't':
			if ((lifetime = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid lifetime\n");
				usage();
			}
			break;
		default:
			usage();
		}
	}
	ac -= optind;
	av += optind;

	if (ac > 0 && (c_flag || k_flag || s_flag || d_flag || D_flag))
		usage();

	if (pkcs11_whitelist == NULL)
		pkcs11_whitelist = xstrdup(DEFAULT_PKCS11_WHITELIST);

	if (ac == 0 && !c_flag && !s_flag) {
		shell = getenv("SHELL");
		if (shell != NULL && (len = strlen(shell)) > 2 &&
		    strncmp(shell + len - 3, "csh", 3) == 0)
			c_flag = 1;
	}
	if (k_flag) {
		const char *errstr = NULL;

		pidstr = getenv(SSH_AGENTPID_ENV_NAME);
		if (pidstr == NULL) {
			fprintf(stderr, "%s not set, cannot kill agent\n",
			    SSH_AGENTPID_ENV_NAME);
			exit(1);
		}
		pid = (int)strtonum(pidstr, 2, INT_MAX, &errstr);
		if (errstr) {
			fprintf(stderr,
			    "%s=\"%s\", which is not a good PID: %s\n",
			    SSH_AGENTPID_ENV_NAME, pidstr, errstr);
			exit(1);
		}
		if (kill(pid, SIGTERM) == -1) {
			perror("kill");
			exit(1);
		}
		format = c_flag ? "unsetenv %s;\n" : "unset %s;\n";
		printf(format, SSH_AUTHSOCKET_ENV_NAME);
		printf(format, SSH_AGENTPID_ENV_NAME);
		printf("echo Agent pid %ld killed;\n", (long)pid);
		exit(0);
	}

	/*
	 * Minimum file descriptors:
	 * stdio (3) + listener (1) + syslog (1 maybe) + connection (1) +
	 * a few spare for libc / stack protectors / sanitisers, etc.
	 */
#define SSH_AGENT_MIN_FDS (3+1+1+1+4)
	if (rlim.rlim_cur < SSH_AGENT_MIN_FDS)
		fatal("%s: file descriptor rlimit %lld too low (minimum %u)",
		    __progname, (long long)rlim.rlim_cur, SSH_AGENT_MIN_FDS);
	maxfds = rlim.rlim_cur - SSH_AGENT_MIN_FDS;

	parent_pid = getpid();

	if (agentsocket == NULL) {
		/* Check if socket path is provided in path */
        agentsocket = getenv("AGENT_SOCKET");
    }
	if (agentsocket == NULL) {
		/* Create private directory for agent socket */
		mktemp_proto(socket_dir, sizeof(socket_dir));
		if (mkdtemp(socket_dir) == NULL) {
			perror("mkdtemp: private socket dir");
			exit(1);
		}
		snprintf(socket_name, sizeof socket_name, "%s/agent.%ld", socket_dir,
		    (long)parent_pid);
	} else {
		/* Try to use specified agent socket */
		socket_dir[0] = '\0';
		strlcpy(socket_name, agentsocket, sizeof socket_name);
	}

	/*
	 * Create socket early so it will exist before command gets run from
	 * the parent.
	 */
	prev_mask = umask(0177);
	sock = unix_listener(socket_name, SSH_LISTEN_BACKLOG, 0);
	if (sock < 0) {
		/* XXX - unix_listener() calls error() not perror() */
		*socket_name = '\0'; /* Don't unlink any existing file */
		cleanup_exit(1);
	}
	umask(prev_mask);

	/*
	 * Fork, and have the parent execute the command, if any, or present
	 * the socket data.  The child continues as the authentication agent.
	 */
	if (D_flag || d_flag) {
		log_init(__progname,
		    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
		    SYSLOG_FACILITY_AUTH, 1);
		format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
		printf(format, SSH_AUTHSOCKET_ENV_NAME, socket_name,
		    SSH_AUTHSOCKET_ENV_NAME);
		printf("echo Agent pid %ld;\n", (long)parent_pid);
		fflush(stdout);
		goto skip;
	}
	pid = fork();
	if (pid == -1) {
		perror("fork");
		cleanup_exit(1);
	}
	if (pid != 0) {		/* Parent - execute the given command. */
		close(sock);
		snprintf(pidstrbuf, sizeof pidstrbuf, "%ld", (long)pid);
		if (ac == 0) {
			format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
			printf(format, SSH_AUTHSOCKET_ENV_NAME, socket_name,
			    SSH_AUTHSOCKET_ENV_NAME);
			printf(format, SSH_AGENTPID_ENV_NAME, pidstrbuf,
			    SSH_AGENTPID_ENV_NAME);
			printf("echo Agent pid %ld;\n", (long)pid);
			exit(0);
		}
		if (setenv(SSH_AUTHSOCKET_ENV_NAME, socket_name, 1) == -1 ||
		    setenv(SSH_AGENTPID_ENV_NAME, pidstrbuf, 1) == -1) {
			perror("setenv");
			exit(1);
		}
		execvp(av[0], av);
		perror(av[0]);
		exit(1);
	}
	/* child */
	log_init(__progname, SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_AUTH, 0);

	if (setsid() == -1) {
		error("setsid: %s", strerror(errno));
		cleanup_exit(1);
	}

	(void)chdir("/");
	if ((fd = open(_PATH_DEVNULL, O_RDWR, 0)) != -1) {
		/* XXX might close listen socket */
		(void)dup2(fd, STDIN_FILENO);
		(void)dup2(fd, STDOUT_FILENO);
		(void)dup2(fd, STDERR_FILENO);
		if (fd > 2)
			close(fd);
	}

#ifdef HAVE_SETRLIMIT
	/* deny core dumps, since memory contains unencrypted private keys */
	rlim.rlim_cur = rlim.rlim_max = 0;
	if (setrlimit(RLIMIT_CORE, &rlim) == -1) {
		error("setrlimit RLIMIT_CORE: %s", strerror(errno));
		cleanup_exit(1);
	}
#endif

skip:

	cleanup_pid = getpid();

#ifdef ENABLE_PKCS11
	pkcs11_init(0);
#endif
	new_socket(AUTH_SOCKET, sock);
	if (ac > 0)
		parent_alive_interval = 10;
	idtab_init();
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, (d_flag | D_flag) ? cleanup_handler : SIG_IGN);
	signal(SIGHUP, cleanup_handler);
	signal(SIGTERM, cleanup_handler);

	if (pledge("stdio rpath cpath unix id proc exec", NULL) == -1)
		fatal("%s: pledge: %s", __progname, strerror(errno));
	platform_pledge_agent();

	while (1) {
		prepare_poll(&pfd, &npfd, &timeout, maxfds);
		result = poll(pfd, npfd, timeout);
		saved_errno = errno;
		if (parent_alive_interval != 0)
			check_parent_exists();
		(void) reaper();	/* remove expired keys */
		if (result == -1) {
			if (saved_errno == EINTR)
				continue;
			fatal("poll: %s", strerror(saved_errno));
		} else if (result > 0)
			after_poll(pfd, npfd, maxfds);
	}
	/* NOTREACHED */
}
