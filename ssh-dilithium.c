/* $OpenBSD: ssh-ecdsa.c,v 1.16 2019/01/21 09:54:11 djm Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
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

#include <string.h>

#include "digest.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "sshkey.h"

#include "crystals/dilithium/avx2/generic_api.h"

#include "openbsd-compat/openssl-compat.h"

int ssh_dilithium_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
                       const u_char *data, size_t datalen, u_int compat) {
  int hash_alg;
  u_char digest[SSH_DIGEST_MAX_LENGTH];
  size_t len, dlen, slen;
  struct sshbuf *b = NULL;
  int ret = SSH_ERR_INTERNAL_ERROR;
  u_char *sig = NULL;

  if (lenp != NULL)
    *lenp = 0;
  if (sigp != NULL)
    *sigp = NULL;

  if (key == NULL || key->dilithium == NULL ||
      sshkey_type_plain(key->type) != KEY_DILITHIUM)
    return SSH_ERR_INVALID_ARGUMENT;

  /* digest data need to be sign */
  if ((hash_alg = sshkey_dilithium_variant_to_hash_alg(key->variant)) == -1 ||
      (dlen = ssh_digest_bytes(hash_alg)) == 0)
    return SSH_ERR_INTERNAL_ERROR;

  if ((ret = ssh_digest_memory(hash_alg, data, datalen, digest,
                               sizeof(digest))) != 0)
    goto out;

  if ((sig = malloc(dilithium_sign_bytes(key->dilithium, dlen))) == NULL) {
    ret = SSH_ERR_ALLOC_FAIL;
    goto out;
  }

  /* signing digest data */
  if (dilithium_sign(sig, (unsigned long long *)&slen, digest, dlen,
                     key->dilithium) != 0) {
    ret = SSH_ERR_LIBCRYPTO_ERROR;
    goto out;
  }

  /* Prepare a buffer to simplifie using of the signature */
  if ((b = sshbuf_new()) == NULL) {
    ret = SSH_ERR_ALLOC_FAIL;
    goto out;
  }

  /* putting name algorithm and signature */
  if ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(key))) != 0 ||
      (ret = sshbuf_put_string(b, sig, slen)) != 0)
    goto out;

  /* writing buffer inside signature ptr */
  len = sshbuf_len(b);
  if (sigp != NULL) {
    if ((*sigp = malloc(len)) == NULL) {
      ret = SSH_ERR_ALLOC_FAIL;
      goto out;
    }
    memcpy(*sigp, sshbuf_ptr(b), len);
  }

  if (lenp != NULL)
    *lenp = len;
  ret = 0;
out:
  explicit_bzero(digest, sizeof(digest));
  sshbuf_free(b);
  freezero(sig, slen);
  return ret;
}

int ssh_dilithium_verify(const struct sshkey *key, const u_char *signature,
                         size_t signaturelen, const u_char *data,
                         size_t datalen, u_int compat) {
  int hash_alg;
  u_char digest[SSH_DIGEST_MAX_LENGTH];
  size_t len, dlen, slen, tlen;
  struct sshbuf *b = NULL;
  int ret = SSH_ERR_INTERNAL_ERROR;
  u_char *msg = NULL, *sigblob = NULL;
  char *sigtype = NULL;

  if (key == NULL || key->dilithium == NULL ||
      sshkey_type_plain(key->type) != KEY_DILITHIUM)
    return SSH_ERR_INVALID_ARGUMENT;

  /* Extract the type of signature and the signature */
  if ((b = sshbuf_from(signature, signaturelen)) == NULL)
    return SSH_ERR_ALLOC_FAIL;

  if (sshbuf_get_cstring(b, &sigtype, &tlen) != 0 ||
      key->type != sshkey_type_from_name(sigtype) ||
      key->variant != sshkey_variant_from_name(sigtype)) {
    ret = SSH_ERR_INVALID_FORMAT;
    goto out;
  }

  if (sshbuf_get_string(b, &sigblob, &slen) != 0) {
    ret = SSH_ERR_INVALID_FORMAT;
    goto out;
  }

  /* digest data to verify the signature */
  if ((hash_alg = sshkey_dilithium_variant_to_hash_alg(key->variant)) == -1 ||
      (dlen = ssh_digest_bytes(hash_alg)) == 0)
    return SSH_ERR_INTERNAL_ERROR;

  if ((ret = ssh_digest_memory(hash_alg, data, datalen, digest,
                               sizeof(digest))) != 0)
    goto out;

  if ((msg = malloc(slen)) == NULL) {
    ret = SSH_ERR_ALLOC_FAIL;
    goto out;
  }

  /* Verify the signature and extract the message */
  if (dilithium_sign_open(msg, (unsigned long long *)&len, sigblob, slen,
                          key->dilithium) != 0) {
    ret = SSH_ERR_SIGNATURE_INVALID;
    goto out;
  }

  /* Compare message to finish the verification */
  if (dlen != len || memcmp(digest, msg, len) != 0) {
    ret = SSH_ERR_SIGNATURE_INVALID;
    goto out;
  }

  ret = 0;
out:
  explicit_bzero(digest, sizeof(digest));
  sshbuf_free(b);
  freezero(msg, slen);
  freezero(sigblob, slen);
  free(sigtype);
  return ret;
}
