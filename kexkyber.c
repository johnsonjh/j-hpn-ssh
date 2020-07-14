/* $OpenBSD: kexc25519.c,v 1.17 2019/01/21 10:40:11 djm Exp $ */
/*
 * Copyright (c) 2019 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
 * Copyright (c) 2013 Aris Adamantiadis.  All rights reserved.
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

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "sshkey.h"
#include "kex.h"
#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"
#include "ssh2.h"

int
kex_kyber_prepare_shared(struct sshbuf *buf, struct sshbuf **sharedp)
{
	u_char *ss = NULL;
	u_char *shaked = NULL;
	u_char *tmp = NULL;
	struct sshbuf *shared = NULL;
	size_t size, ss_len = 2 * kyber_ss_bytes(), shaked_len = kyber_ss_bytes();
	int r = -1;

	/* Prepare buffer to store concated nonce and result of shake */
	if ((ss = malloc(ss_len)) == NULL ||
		(shaked = malloc(shaked_len)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* prepare output buffer with the shared secret */
	if ((shared = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* Read first Nonce and write it in the buffer */
	if ((r = sshbuf_get_string_direct(buf, &tmp, &size)))
		goto out;

	memcpy(ss, tmp, size);

	/* Read second Nonce and write it in the buffer */
	if ((r = sshbuf_get_string_direct(buf, &tmp, &size)))
		goto out;

	memcpy(ss + kyber_ss_bytes(), tmp, size);

	/* generate shared secret */
	kyber_shake(shaked, shaked_len, ss, ss_len);

	/* store shared secret */
	if ((r = sshbuf_put_string(shared, shaked, shaked_len)) != 0)
		goto out;

	*sharedp = shared;
	shared = NULL;

	r = 0;
out:
	freezero(ss, ss_len);
	freezero(shaked, shaked_len);
	sshbuf_free(shared);
	return r;
}

int
kex_kyber_keypair(struct kex *kex)
{
	struct sshbuf *buf = NULL;
	u_char *client_public = NULL;
	int r = -1;

	if ((buf = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if ((kex->kyber = kyber_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if (kyber_prepare(kex->kyber, KYBER512) != 0) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	
	/* generate keys */
	if (kyber_generate_key(kex->kyber) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	/* save public key */
	if ((r = sshbuf_put_string(buf, kex->kyber->pk,
		kyber_pk_bytes(kex->kyber))) != 0)
		goto out;

	kex->client_pub = buf;
	buf = NULL;
	r = 0;
 out:
	sshbuf_free(buf);
	return r;
}

int
kex_kyber_shared_to_client(struct kex *kex, const struct sshbuf *client_pubkey,
	struct sshbuf **server_pubkeyp, struct sshbuf **blob_toclientp, struct sshbuf **noncep)
{
	KYBER client;
	u_char *ct = NULL, *ss = NULL;
	struct sshbuf *server_pubkey = NULL;
	struct sshbuf *blob_toclient = NULL;
	struct sshbuf *client_pubkey_tmp = NULL;
	struct sshbuf *nonce = NULL;
	size_t size;
	int r = -1;

	/* preserve client_pubkey */
	if ((client_pubkey_tmp = sshbuf_fromb(client_pubkey)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* recover client public key */
	client.type = KYBER512;
	if ((r = sshbuf_get_string(client_pubkey_tmp, &(client.pk),
		&size )) != 0)
		return r;

	/* generate temporal server keys */
	if ((r = kex_kyber_keypair(kex)) != 0)
		goto out;

	/* init buffer for the server public key */
	if ((server_pubkey = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* put temporal server public key need to be transfer */
	if ((r = sshbuf_put_string(server_pubkey, kex->kyber->pk,
		kyber_pk_bytes(kex->kyber))) != 0)
		goto out;

	/* init shared secret, buffer for client blob, nonce to sign */
	if ((kex->tshared = sshbuf_new()) == NULL ||
		(blob_toclient = sshbuf_new()) == NULL ||
		(nonce = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* init intermediate variable to kyber enc */
	if ((ct = malloc(kyber_enc_bytes(&client))) == NULL ||
	   (ss = malloc(kyber_ss_bytes())) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* generate Nonce */
	if (kyber_enc(ct, ss, &client) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	/* put ciphertext to client blob */
	if ((r = sshbuf_put_string(blob_toclient, ct,
		kyber_enc_bytes(&client))) != 0)
		goto out;

	/* store nonce */
	if ((r = sshbuf_put_string(nonce, ss,
		kyber_ss_bytes())) != 0)
		goto out;

	/* add to shared secret */
	if ((r = sshbuf_put_string(kex->tshared, ss,
		kyber_ss_bytes())) != 0)
		goto out;

	*server_pubkeyp = server_pubkey;
	*blob_toclientp = blob_toclient;
	*noncep = nonce;
	server_pubkey = NULL;
	blob_toclient = NULL;
	nonce = NULL;

	r = 0;
out:
	freezero(ct, kyber_enc_bytes(&client));
	freezero(ss, kyber_ss_bytes());
	sshbuf_free(server_pubkey);
	sshbuf_free(blob_toclient);
	sshbuf_free(client_pubkey_tmp);
	sshbuf_free(nonce);
	free(client.pk);

	return r;
}

int
kex_kyber_shared_to_server(struct kex *kex, const struct sshbuf *server_pubkey, 
	const struct sshbuf *blob_fromserver, struct sshbuf **blob_toserverp, struct sshbuf **sharedp, struct sshbuf **noncep)
{
	KYBER server;
	u_char *ct = NULL, *ss = NULL, *ss_fromserver = NULL, *ct_fromserver = NULL;
	struct sshbuf *blob_toserver = NULL;
	struct sshbuf *shared = NULL;
	struct sshbuf *server_pubkey_tmp = NULL;
	struct sshbuf *blob_fromserver_tmp = NULL;
	struct sshbuf *tmp = NULL;
	struct sshbuf *nonce = NULL;
	size_t size;
	int r;

	/* preserve server_pubkey_tmp */
	if ((server_pubkey_tmp = sshbuf_fromb(server_pubkey)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* recover server public key */
	server.type = KYBER512;
	size = kyber_pk_bytes(&server); 
	if ((r = sshbuf_get_string(server_pubkey_tmp, &(server.pk),
		&size)) != 0)
		return r;

	/* init buffer for server blob, nonce to verify sign and tmp*/
	if ((blob_toserver = sshbuf_new()) == NULL ||
		(kex->tshared = sshbuf_new()) == NULL ||
		(nonce = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* init intermediate variable to kyber dec and enc */
	if ((ct = malloc(kyber_enc_bytes(kex->kyber))) == NULL ||
	    (ss = malloc(kyber_ss_bytes())) == NULL ||
	   	(ss_fromserver = malloc(kyber_ss_bytes())) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* preserve blob_fromserver_tmp */
	if ((blob_fromserver_tmp = sshbuf_fromb(blob_fromserver)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* get ciphertext from server */
	if ((r = sshbuf_get_string(blob_fromserver_tmp, &ct_fromserver, &size)))
		goto out;

	/* decrypt Nonce from server */
	if (kyber_dec(ss_fromserver, ct_fromserver, kex->kyber) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	/* save ss from server */
	if ((r = sshbuf_put_string(kex->tshared, ss_fromserver,
		kyber_ss_bytes())) != 0)
		goto out;

	/* store to nonce to verify signature and generate hash */
	if ((r = sshbuf_put_string(nonce, ss_fromserver,
		kyber_ss_bytes())) != 0)
		goto out;

	/* generate Nonce */
	if (kyber_enc(ct, ss, &server) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	/* put ciphertext to client blob */
	if ((r = sshbuf_put_string(blob_toserver, ct,
		kyber_enc_bytes(&server))) != 0)
		goto out;

	/* add to tmp */
	if ((r = sshbuf_put_string(kex->tshared, ss,
		kyber_ss_bytes())) != 0)
		goto out;

	/* compute shared secret */
	if ((r = kex_kyber_prepare_shared(kex->tshared, &shared)) != 0)
		goto out;
	
	*sharedp = shared;
	*blob_toserverp = blob_toserver;
	*noncep = nonce;
	nonce = NULL;
	shared = NULL;
	blob_toserver = NULL;

	r = 0;
out:
	freezero(ct_fromserver, kyber_enc_bytes(&server));
	freezero(ss_fromserver, kyber_ss_bytes());
	freezero(ct, kyber_enc_bytes(&server));
	freezero(ss, kyber_ss_bytes());
	sshbuf_free(blob_toserver);
	sshbuf_free(shared);
	sshbuf_free(server_pubkey_tmp);
	sshbuf_free(blob_fromserver_tmp);
	sshbuf_free(nonce);
	free(server.pk);
	return r;
}

int
kex_kyber_compute_shared(struct kex *kex, const struct sshbuf *blob_fromclient, struct sshbuf **sharedp)
{
	u_char *ct_fromclient = NULL, *ss_fromclient = NULL;
	struct sshbuf *shared = NULL;
	struct sshbuf *blob_fromclient_tmp = NULL;
	int r = -1;

	/* init intermediate variable to kyber dec */
	if ((ss_fromclient = malloc(kyber_enc_bytes(kex->kyber))) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	/* preserve blob_fromclient */
	if ((blob_fromclient_tmp = sshbuf_fromb(blob_fromclient)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* get ciphertext from client */
	if ((r = sshbuf_get_string(blob_fromclient , &ct_fromclient, kyber_enc_bytes(&(kex->kyber)))))
		goto out;

	/* decrypt Nonce from client */
	if (kyber_dec(ss_fromclient, ct_fromclient, kex->kyber) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	/* save ss from client */
	if ((r = sshbuf_put_string(kex->tshared, ss_fromclient,
		kyber_ss_bytes())) != 0)
		goto out;

	/* compute shared secret */
	if ((r = kex_kyber_prepare_shared(kex->tshared, &shared)) != 0)
		goto out;
	
	*sharedp = shared;
	shared = NULL;

	r = 0;
out:
	sshbuf_free(shared);
	sshbuf_free(blob_fromclient_tmp);
	freezero(ct_fromclient, kyber_enc_bytes(kex->kyber));
	freezero(ss_fromclient, kyber_ss_bytes());

	return r;
}

