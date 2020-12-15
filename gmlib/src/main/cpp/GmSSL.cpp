/* ====================================================================
 * Copyright (c) 2014 - 2017 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <jni.h>
#include <android/log.h>
#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

#ifndef OPENSSL_NO_CMAC

# include <openssl/cmac.h>

#endif
#ifndef OPENSSL_NO_SM2

#include <openssl/sm2.h>

#endif

#include <openssl/x509.h>
#include <openssl/stack.h>
#include <openssl/crypto.h>
#include <openssl/safestack.h>
//#include "../e_os.h"
//#include "gmssl_err.c"
//#include "GmSSL.h"

#define GMSSL_JNI_VERSION    "GmSSL-JNI MEGVII API/1.1 2020-12-15"
#define LOG_TAG "MEGVII_GMSSL_JNI"

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define NUM_ARRAY_ELEMENTS(p) ((int) sizeof(p) / sizeof(p[0]))
#define OSSL_NELEM(x) (sizeof(x)/sizeof((x)[0]))


JNIEXPORT jobjectArray JNICALL getVersions(JNIEnv *env, jclass thiz) {
    jobjectArray ret = NULL;
    int i;

    if (!(ret = env->NewObjectArray(7, env->FindClass("java/lang/String"),
                                    env->NewStringUTF("")))) {
        LOGE("getVersions NewObjectArray failed");
        return NULL;
    }

    env->SetObjectArrayElement(ret, 0, env->NewStringUTF(GMSSL_JNI_VERSION));

    for (i = 1; i < 7; i++) {
        env->SetObjectArrayElement(ret, i, env->NewStringUTF(OpenSSL_version(i - 1)));
    }

    return ret;
}

static void list_cipher_fn(const EVP_CIPHER *c, const char *from, const char *to, void *argv) {
    STACK_OF(OPENSSL_CSTRING) *sk = static_cast<stack_st_OPENSSL_CSTRING *>(argv);
    if (c) {
        sk_OPENSSL_CSTRING_push(sk, EVP_CIPHER_name(c));
    } else {
        sk_OPENSSL_CSTRING_push(sk, from);
    }
}

JNIEXPORT jobjectArray JNICALL getCiphers(JNIEnv *env, jclass thiz) {
    jobjectArray ret = NULL;
    STACK_OF(OPENSSL_CSTRING) *sk = NULL;
    int i;

    if (!(sk = sk_OPENSSL_CSTRING_new_null())) {
        LOGE("getCiphers sk_OPENSSL_CSTRING_new_null() failed");
        goto end;
    }

    EVP_CIPHER_do_all_sorted(list_cipher_fn, sk);

    if (!(ret = env->NewObjectArray(sk_OPENSSL_CSTRING_num(sk), env->FindClass("java/lang/String"),
                                    env->NewStringUTF("")))) {
        LOGE("getCiphers NewObjectArray failed");
        goto end;
    }

    for (i = 0; i < sk_OPENSSL_CSTRING_num(sk); i++) {
        env->SetObjectArrayElement(ret, i, env->NewStringUTF(sk_OPENSSL_CSTRING_value(sk, i)));
    }
    end:
    sk_OPENSSL_CSTRING_free(sk);
    return ret;
}

static void list_md_fn(const EVP_MD *md, const char *from, const char *to, void *argv) {
    STACK_OF(OPENSSL_CSTRING) *sk = static_cast<stack_st_OPENSSL_CSTRING *>(argv);
    if (md) {
        sk_OPENSSL_CSTRING_push(sk, EVP_MD_name(md));
    } else {
        sk_OPENSSL_CSTRING_push(sk, from);
    }
}

JNIEXPORT jobjectArray JNICALL getDigests(JNIEnv *env, jclass thiz) {
    jobjectArray ret = NULL;
    STACK_OF(OPENSSL_CSTRING) *sk = NULL;
    int i;

    if (!(sk = sk_OPENSSL_CSTRING_new_null())) {
        LOGE("getDigests sk_OPENSSL_CSTRING_new_null() failed");
        goto end;
    }
    EVP_MD_do_all_sorted(list_md_fn, sk);

    if (!(ret = env->NewObjectArray(sk_OPENSSL_CSTRING_num(sk),
                                    env->FindClass("java/lang/String"),
                                    env->NewStringUTF("")))) {
        LOGE("getDigests NewObjectArray failed");
        goto end;
    }

    for (i = 0; i < sk_OPENSSL_CSTRING_num(sk); i++) {
        env->SetObjectArrayElement(ret, i, env->NewStringUTF(sk_OPENSSL_CSTRING_value(sk, i)));
    }

    end:
    sk_OPENSSL_CSTRING_free(sk);
    return ret;
}

char *mac_algors[] = {
        "CMAC-SMS4",
        "HMAC-SM3",
        "HMAC-SHA1",
        "HMAC-SHA256",
        "HMAC-SHA512",
};

JNIEXPORT jobjectArray JNICALL getMacs(JNIEnv *env, jclass thiz) {
    jobjectArray ret = NULL;
    int i;
    if (!(ret = env->NewObjectArray(OSSL_NELEM(mac_algors),
                                    env->FindClass("java/lang/String"),
                                    env->NewStringUTF("")))) {
        LOGE("getMacs NewObjectArray failed");
        return NULL;
    }

    for (i = 0; i < OSSL_NELEM(mac_algors); i++) {
        env->SetObjectArrayElement(ret, i, env->NewStringUTF(mac_algors[i]));
    }

    return ret;
}

int sign_nids[] = {
#ifndef OPENSSL_NO_SM2
        NID_sm2sign,
#endif
        NID_ecdsa_with_Recommended,
#ifndef OPENSSL_NO_SHA
        NID_ecdsa_with_SHA1,
        NID_ecdsa_with_SHA256,
        NID_ecdsa_with_SHA512,
# ifndef OPENSSL_NO_RSA
        NID_sha1WithRSAEncryption,
        NID_sha256WithRSAEncryption,
        NID_sha512WithRSAEncryption,
# endif
# ifndef OPENSSL_NO_DSA
        NID_dsaWithSHA1,
# endif
#endif
};

JNIEXPORT jobjectArray JNICALL getSignAlgorithms(JNIEnv *env, jclass thiz) {
    jobjectArray ret = NULL;
    int num_algors = sizeof(sign_nids) / sizeof(sign_nids[0]);
    int i;
    if (!(ret = env->NewObjectArray(OSSL_NELEM(sign_nids),
                                    env->FindClass("java/lang/String"),
                                    env->NewStringUTF("")))) {
        LOGE("getSignAlgorithms NewObjectArray failed");
        return NULL;
    }

    for (i = 0; i < num_algors; i++) {
        env->SetObjectArrayElement(ret, i, env->NewStringUTF(OBJ_nid2sn(sign_nids[i])));
    }

    return ret;
}

int pke_nids[] = {
#ifndef OPENSSL_NO_RSA
        NID_rsaesOaep,
#endif
#ifndef OPENSSL_NO_ECIES
        NID_ecies_recommendedParameters,
        NID_ecies_specifiedParameters,
# ifndef OPENSSL_NO_SHA
        NID_ecies_with_x9_63_sha1_xor_hmac,
        NID_ecies_with_x9_63_sha256_xor_hmac,
        NID_ecies_with_x9_63_sha512_xor_hmac,
        NID_ecies_with_x9_63_sha1_aes128_cbc_hmac,
        NID_ecies_with_x9_63_sha256_aes128_cbc_hmac,
        NID_ecies_with_x9_63_sha512_aes256_cbc_hmac,
        NID_ecies_with_x9_63_sha256_aes128_ctr_hmac,
        NID_ecies_with_x9_63_sha512_aes256_ctr_hmac,
        NID_ecies_with_x9_63_sha256_aes128_cbc_hmac_half,
        NID_ecies_with_x9_63_sha512_aes256_cbc_hmac_half,
        NID_ecies_with_x9_63_sha256_aes128_ctr_hmac_half,
        NID_ecies_with_x9_63_sha512_aes256_ctr_hmac_half,
        NID_ecies_with_x9_63_sha1_aes128_cbc_cmac,
        NID_ecies_with_x9_63_sha256_aes128_cbc_cmac,
        NID_ecies_with_x9_63_sha512_aes256_cbc_cmac,
        NID_ecies_with_x9_63_sha256_aes128_ctr_cmac,
        NID_ecies_with_x9_63_sha512_aes256_ctr_cmac,
# endif
#endif
#ifndef OPENSSL_NO_SM2
        NID_sm2encrypt_with_sm3,
# ifndef OPENSSL_NO_SHA
        NID_sm2encrypt_with_sha1,
        NID_sm2encrypt_with_sha256,
        NID_sm2encrypt_with_sha512,
# endif
#endif
};

JNIEXPORT jobjectArray JNICALL getPublicKeyEncryptions(JNIEnv *env, jclass thiz) {
    jobjectArray ret = NULL;
    int i;

    if (!(ret = env->NewObjectArray(OSSL_NELEM(pke_nids),
                                    env->FindClass("java/lang/String"),
                                    env->NewStringUTF("")))) {
        LOGE("getPublicKeyEncryptions NewObjectArray failed");
        return NULL;
    }

    for (i = 0; i < OSSL_NELEM(pke_nids); i++) {
        env->SetObjectArrayElement(ret, i, env->NewStringUTF(OBJ_nid2sn(pke_nids[i])));
    }

    return ret;
}

int exch_nids[] = {
#ifndef OPENSSL_NO_SM2
        NID_sm2exchange,
#endif
#ifndef OPENSSL_NO_SHA
        NID_dhSinglePass_stdDH_sha1kdf_scheme,
        NID_dhSinglePass_stdDH_sha224kdf_scheme,
        NID_dhSinglePass_stdDH_sha256kdf_scheme,
        NID_dhSinglePass_stdDH_sha384kdf_scheme,
        NID_dhSinglePass_stdDH_sha512kdf_scheme,
        NID_dhSinglePass_cofactorDH_sha1kdf_scheme,
        NID_dhSinglePass_cofactorDH_sha224kdf_scheme,
        NID_dhSinglePass_cofactorDH_sha256kdf_scheme,
        NID_dhSinglePass_cofactorDH_sha384kdf_scheme,
        NID_dhSinglePass_cofactorDH_sha512kdf_scheme,
#endif
#ifndef OPENSSL_NO_DH
        NID_dhKeyAgreement,
#endif
};

JNIEXPORT jobjectArray JNICALL getDeriveKeyAlgorithms(JNIEnv *env, jclass thiz) {
    jobjectArray ret = NULL;
    int i;

    if (!(ret = env->NewObjectArray(OSSL_NELEM(exch_nids), env->FindClass("java/lang/String"),
                                    env->NewStringUTF("")))) {
        LOGE("getDeriveKeyAlgorithms NewObjectArray failed");
        return NULL;
    }

    for (i = 0; i < OSSL_NELEM(exch_nids); i++) {
        env->SetObjectArrayElement(ret, i, env->NewStringUTF(OBJ_nid2sn(exch_nids[i])));
    }

    return ret;
}

JNIEXPORT jbyteArray JNICALL generateRandom(JNIEnv *env, jclass clazz, jint outlen) {
    jbyteArray ret = NULL;
    void *outbuf = NULL;

    if (outlen <= 0 || outlen >= INT_MAX) {
        LOGE("generateRandom outlen invalid");
        return NULL;
    }

    if (!(outbuf = OPENSSL_malloc(outlen))) {
        LOGE("generateRandom OPENSSL_malloc failed");
        goto end;
    }

    if (!RAND_bytes((unsigned char *) outbuf, outlen)) {
        LOGE("generateRandom RAND_bytes failed");
        goto end;
    }
    if (!(ret = env->NewByteArray(outlen))) {
        LOGE("generateRandom NewByteArray failed");
        goto end;
    }

    env->SetByteArrayRegion(ret, 0, outlen, (jbyte *) outbuf);

    end:
    OPENSSL_free(outbuf);
    return ret;
}

JNIEXPORT jint JNICALL getCipherIVLength(JNIEnv *env, jclass thiz, jstring algor) {
    jint ret = -1;
    const char *alg = NULL;
    const EVP_CIPHER *cipher;

    if (!(alg = env->GetStringUTFChars(algor, 0))) {
        LOGE("getCipherIVLength GetStringUTFChars failed");
        goto end;
    }

    if (!(cipher = EVP_get_cipherbyname(alg))) {
        LOGE("getCipherIVLength EVP_get_cipherbyname failed");
        goto end;
    }

    ret = EVP_CIPHER_iv_length(cipher);

    end:
    env->ReleaseStringUTFChars(algor, alg);
    return ret;
}

JNIEXPORT jint JNICALL getCipherKeyLength(JNIEnv *env, jclass thiz, jstring algor) {
    jint ret = -1;
    const char *alg = NULL;
    const EVP_CIPHER *cipher;

    if (!(alg = env->GetStringUTFChars(algor, 0))) {
        LOGE("getCipherKeyLength GetStringUTFChars failed");
        goto end;
    }

    if (!(cipher = EVP_get_cipherbyname(alg))) {
        LOGE("getCipherKeyLength EVP_get_cipherbyname failed");
        goto end;
    }

    ret = EVP_CIPHER_key_length(cipher);

    end:
    if (alg) env->ReleaseStringUTFChars(algor, alg);
    return ret;
}

JNIEXPORT jint JNICALL getCipherBlockSize(JNIEnv *env, jclass thiz, jstring algor) {
    jint ret = -1;
    const char *alg = NULL;
    const EVP_CIPHER *cipher;

    if (!(alg = env->GetStringUTFChars(algor, 0))) {
        LOGE("getCipherBlockSize GetStringUTFChars failed");
        goto end;
    }

    if (!(cipher = EVP_get_cipherbyname(alg))) {
        LOGE("getCipherBlockSize EVP_get_cipherbyname failed");
        goto end;
    }

    ret = EVP_CIPHER_block_size(cipher);

    end:
    if (alg) env->ReleaseStringUTFChars(algor, alg);
    return ret;
}

JNIEXPORT jbyteArray JNICALL symmetricEncrypt(JNIEnv *env, jclass thiz, jstring algor,
                                              jbyteArray in, jbyteArray key, jbyteArray iv) {
    jbyteArray ret = NULL;
    const char *alg = NULL;
    const unsigned char *keybuf = NULL;
    const unsigned char *ivbuf = NULL;
    const unsigned char *inbuf = NULL;
    void *outbuf = NULL;
    int inlen, keylen, ivlen, outlen, lastlen;
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX *cctx = NULL;

    if (!(alg = env->GetStringUTFChars(algor, 0))) {
        LOGE("symmetricEncrypt GetStringUTFChars failed");
        goto end;
    }
    if (!(inbuf = (unsigned char *) env->GetByteArrayElements(in, 0))) {
        LOGE("symmetricEncrypt GetByteArrayElements failed");
        goto end;
    }
    if ((inlen = env->GetArrayLength(in)) <= 0) {
        LOGE("symmetricEncrypt GetArrayLength failed");
        goto end;
    }
    if (!(keybuf = (unsigned char *) env->GetByteArrayElements(key, 0))) {
        LOGE("symmetricEncrypt GetByteArrayElements 2 failed");
        goto end;
    }
    if ((keylen = env->GetArrayLength(key)) <= 0) {
        LOGE("symmetricEncrypt GetArrayLength 2 failed");
        goto end;
    }
    ivbuf = (unsigned char *) env->GetByteArrayElements(iv, 0);
    ivlen = env->GetArrayLength(iv);

    if (!(cipher = EVP_get_cipherbyname(alg))) {
        LOGE("symmetricEncrypt EVP_get_cipherbyname failed");
        goto end;
    }
    if (keylen != EVP_CIPHER_key_length(cipher)) {
        LOGE("symmetricEncrypt EVP_CIPHER_key_length failed");
        goto end;
    }
    if (ivlen != EVP_CIPHER_iv_length(cipher)) {
        LOGE("symmetricEncrypt EVP_CIPHER_iv_length failed");
        goto end;
    }
    if (!(outbuf = OPENSSL_malloc(inlen + 2 * EVP_CIPHER_block_size(cipher)))) {
        LOGE("symmetricEncrypt OPENSSL_malloc failed");
        goto end;
    }
    if (!(cctx = EVP_CIPHER_CTX_new())) {
        LOGE("symmetricEncrypt EVP_CIPHER_CTX_new failed");
        goto end;
    }
    if (!EVP_EncryptInit_ex(cctx, cipher, NULL, keybuf, ivbuf)) {
        LOGE("symmetricEncrypt EVP_EncryptInit_ex failed");
        goto end;
    }
    if (!EVP_EncryptUpdate(cctx, (unsigned char *) outbuf, &outlen, inbuf, inlen)) {
        LOGE("symmetricEncrypt EVP_EncryptUpdate failed");
        goto end;
    }
    if (!EVP_EncryptFinal_ex(cctx, (unsigned char *) outbuf + outlen, &lastlen)) {
        LOGE("symmetricEncrypt EVP_EncryptFinal_ex failed");
        goto end;
    }
    outlen += lastlen;

    if (!(ret = env->NewByteArray(outlen))) {
        LOGE("symmetricEncrypt NewByteArray failed");
        goto end;
    }

    env->SetByteArrayRegion(ret, 0, outlen, (jbyte *) outbuf);

    end:
    if (alg) env->ReleaseStringUTFChars(algor, alg);
    if (keybuf) env->ReleaseByteArrayElements(key, (jbyte *) keybuf, JNI_ABORT);
    if (inbuf) env->ReleaseByteArrayElements(in, (jbyte *) inbuf, JNI_ABORT);
    if (ivbuf) env->ReleaseByteArrayElements(iv, (jbyte *) ivbuf, JNI_ABORT);
    OPENSSL_free(outbuf);
    EVP_CIPHER_CTX_free(cctx);
    return ret;
}

JNIEXPORT jbyteArray JNICALL symmetricDecrypt(JNIEnv *env, jclass thiz, jstring algor,
                                              jbyteArray in, jbyteArray key, jbyteArray iv) {
    jbyteArray ret = NULL;
    const char *alg = NULL;
    const unsigned char *inbuf = NULL;
    const unsigned char *keybuf = NULL;
    const unsigned char *ivbuf = NULL;
    void *outbuf = NULL;
    int inlen, keylen, ivlen, outlen, lastlen;
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX *cctx = NULL;

    if (!(alg = env->GetStringUTFChars(algor, 0))) {
        LOGE("symmetricDecrypt GetStringUTFChars failed");
        goto end;
    }
    if (!(inbuf = (unsigned char *) env->GetByteArrayElements(in, 0))) {
        LOGE("symmetricDecrypt GetByteArrayElements failed");
        goto end;
    }
    if ((inlen = env->GetArrayLength(in)) <= 0) {
        LOGE("symmetricDecrypt GetArrayLength failed");
        goto end;
    }
    if (!(keybuf = (unsigned char *) env->GetByteArrayElements(key, 0))) {
        LOGE("symmetricDecrypt GetByteArrayElements 2 failed");
        goto end;
    }
    if ((keylen = env->GetArrayLength(key)) <= 0) {
        LOGE("symmetricDecrypt GetArrayLength 2 failed");
        goto end;
    }
    ivbuf = (unsigned char *) env->GetByteArrayElements(iv, 0);
    ivlen = env->GetArrayLength(iv);


    if (!(cipher = EVP_get_cipherbyname(alg))) {
        LOGE("symmetricDecrypt EVP_get_cipherbyname failed");
        goto end;
    }
    if (keylen != EVP_CIPHER_key_length(cipher)) {
        LOGE("symmetricDecrypt EVP_CIPHER_key_length failed");
        goto end;
    }
    if (ivlen != EVP_CIPHER_iv_length(cipher)) {
        LOGE("symmetricDecrypt EVP_CIPHER_iv_length failed");
        goto end;
    }
    if (!(outbuf = OPENSSL_malloc(inlen))) {
        LOGE("symmetricDecrypt OPENSSL_malloc failed");
        goto end;
    }
    if (!(cctx = EVP_CIPHER_CTX_new())) {
        LOGE("symmetricDecrypt EVP_CIPHER_CTX_new failed");
        goto end;
    }
    if (!EVP_DecryptInit_ex(cctx, cipher, NULL, keybuf, ivbuf)) {
        LOGE("symmetricDecrypt EVP_DecryptInit_ex failed");
        goto end;
    }
    if (!EVP_DecryptUpdate(cctx, (unsigned char *) outbuf, &outlen, inbuf, inlen)) {
        LOGE("symmetricDecrypt EVP_DecryptUpdate failed");
        goto end;
    }
    if (!EVP_DecryptFinal_ex(cctx, (unsigned char *) outbuf + outlen, &lastlen)) {
        LOGE("symmetricDecrypt EVP_DecryptFinal_ex failed");
        goto end;
    }
    outlen += lastlen;

    if (!(ret = env->NewByteArray(outlen))) {
        LOGE("symmetricDecrypt NewByteArray failed");
    }

    env->SetByteArrayRegion(ret, 0, outlen, (jbyte *) outbuf);

    end:
    if (alg) env->ReleaseStringUTFChars(algor, alg);
    if (keybuf) env->ReleaseByteArrayElements(key, (jbyte *) keybuf, JNI_ABORT);
    if (inbuf) env->ReleaseByteArrayElements(in, (jbyte *) inbuf, JNI_ABORT);
    if (ivbuf) env->ReleaseByteArrayElements(iv, (jbyte *) ivbuf, JNI_ABORT);
    EVP_CIPHER_CTX_free(cctx);
    return ret;
}

JNIEXPORT jint JNICALL getDigestLength(JNIEnv *env, jclass thiz, jstring algor) {
    jint ret = -1;
    const char *alg = NULL;
    const EVP_MD *md;

    if (!(alg = env->GetStringUTFChars(algor, 0))) {
        LOGE("getDigestLength GetStringUTFChars failed");
        goto end;
    }

    if (!(md = EVP_get_digestbyname(alg))) {
        LOGE("getDigestLength EVP_get_digestbyname failed");
        goto end;
    }

    ret = EVP_MD_size(md);

    end:
    if (alg) env->ReleaseStringUTFChars(algor, alg);
    return ret;
}

JNIEXPORT jint JNICALL getDigestBlockSize(JNIEnv *env, jclass thiz, jstring algor) {
    jint ret = -1;
    const char *alg = NULL;
    const EVP_MD *md;

    if (!(alg = env->GetStringUTFChars(algor, 0))) {
        LOGE("getDigestBlockSize GetStringUTFChars failed");
        goto end;
    }

    if (!(md = EVP_get_digestbyname(alg))) {
        LOGE("getDigestBlockSize EVP_get_digestbyname failed");
        goto end;
    }

    ret = EVP_MD_block_size(md);

    end:
    env->ReleaseStringUTFChars(algor, alg);
    return ret;
}

JNIEXPORT jbyteArray JNICALL digest(JNIEnv *env, jclass thiz, jstring algor, jbyteArray in) {
    jbyteArray ret = NULL;
    const char *alg = NULL;
    const unsigned char *inbuf = NULL;
    unsigned char outbuf[EVP_MAX_MD_SIZE];
    int inlen;
    unsigned int outlen = sizeof(outbuf);
    const EVP_MD *md;

    if (!(alg = env->GetStringUTFChars(algor, 0))) {
        LOGE("digest GetStringUTFChars failed");
        goto end;
    }
    if (!(inbuf = (unsigned char *) env->GetByteArrayElements(in, 0))) {
        LOGE("digest GetByteArrayElements failed");
        goto end;
    }
    if ((inlen = (size_t) env->GetArrayLength(in)) <= 0) {
        LOGE("digest GetArrayLength failed");
        goto end;
    }

    if (!(md = EVP_get_digestbyname(alg))) {
        LOGE("digest EVP_get_digestbyname failed");
        goto end;
    }
    if (!EVP_Digest(inbuf, inlen, outbuf, &outlen, md, NULL)) {
        LOGE("digest EVP_Digest failed");
        goto end;
    }

    if (!(ret = env->NewByteArray(outlen))) {
        LOGE("digest NewByteArray failed");
        goto end;
    }

    env->SetByteArrayRegion(ret, 0, outlen, (jbyte *) outbuf);

    end:
    if (alg) env->ReleaseStringUTFChars(algor, alg);
    if (inbuf) env->ReleaseByteArrayElements(in, (jbyte *) inbuf, JNI_ABORT);
    return ret;
}

JNIEXPORT jbyteArray JNICALL mac(JNIEnv *env, jclass thiz,
                                 jstring algor, jbyteArray in, jbyteArray key) {
    jbyteArray ret = NULL;
    const char *alg = NULL;
    const unsigned char *inbuf = NULL;
    const unsigned char *keybuf = NULL;
    unsigned char outbuf[EVP_MAX_MD_SIZE];
    int inlen, keylen, outlen = sizeof(outbuf);
#ifndef OPENSSL_NO_CMAC
    CMAC_CTX *cctx = NULL;
#endif

    if (!(alg = env->GetStringUTFChars(algor, 0))) {
        LOGE("mac GetStringUTFChars failed");
        goto end;
    }
    if (!(inbuf = (unsigned char *) env->GetByteArrayElements(in, 0))) {
        LOGE("mac GetByteArrayElements failed");
        goto end;
    }
    if ((inlen = env->GetArrayLength(in)) <= 0) {
        LOGE("mac GetArrayLength failed");
        goto end;
    }
    if (!(keybuf = (unsigned char *) env->GetByteArrayElements(key, 0))) {
        LOGE("mac GetByteArrayElements 2 failed");
        goto end;
    }
    if ((keylen = env->GetArrayLength(key)) <= 0) {
        LOGE("mac GetArrayLength 2 failed");
        goto end;
    }

    if (memcmp(alg, "HMAC-", strlen("HMAC-")) == 0) {
        const EVP_MD *md;
        unsigned int len = sizeof(outbuf);

        if (!(md = EVP_get_digestbyname(alg + strlen("HMAC-")))) {
            LOGE("mac EVP_get_digestbyname failed");
            goto end;
        }

        if (!HMAC(md, keybuf, keylen, inbuf, inlen, outbuf, &len)) {
            LOGE("mac HMAC failed");
            goto end;
        }

        outlen = len;

#ifndef OPENSSL_NO_CMAC
    } else if (memcmp(alg, "CMAC-", strlen("CMAC-")) == 0) {
        const EVP_CIPHER *cipher;
        size_t len = sizeof(outbuf);

        if (!(cipher = EVP_get_cipherbyname(alg + strlen("CMAC-")))) {
            LOGE("mac EVP_get_cipherbyname failed");
            goto end;
        }
        if (!(cctx = CMAC_CTX_new())) {
            LOGE("mac CMAC_CTX_new failed");
            goto end;
        }
        if (!CMAC_Init(cctx, keybuf, keylen, cipher, NULL)) {
            LOGE("mac CMAC_Init failed");
            goto end;
        }
        if (!CMAC_Update(cctx, inbuf, inlen)) {
            LOGE("mac CMAC_Update failed");
            goto end;
        }
        if (!CMAC_Final(cctx, outbuf, &len)) {
            LOGE("mac CMAC_Final failed");
            goto end;
        }

        outlen = len;
#endif
    } else {
        goto end;
    }

    if (!(ret = env->NewByteArray(outlen))) {
        LOGE("mac NewByteArray failed");
        goto end;
    }

    env->SetByteArrayRegion(ret, 0, outlen, (jbyte *) outbuf);

    end:
    if (alg) env->ReleaseStringUTFChars(algor, alg);
    if (keybuf) env->ReleaseByteArrayElements(key, (jbyte *) keybuf, JNI_ABORT);
    if (inbuf) env->ReleaseByteArrayElements(in, (jbyte *) inbuf, JNI_ABORT);
#ifndef OPENSSL_NO_CMAC
    CMAC_CTX_free(cctx);
#endif
    return ret;
}

/** jni中定义的JNINativeMethod
 * typedef struct {
    const char* name; //Java方法的名字
    const char* signature; //Java方法的签名信息
    void*       fnPtr; //JNI中对应的方法指针
} JNINativeMethod;
 */
static JNINativeMethod methods[] = {
        {"getVersions",             "()[Ljava/lang/String;",        (void *) getVersions},
        {"getCiphers",              "()[Ljava/lang/String;",        (void *) getCiphers},
        {"getDigests",              "()[Ljava/lang/String;",        (void *) getDigests},
        {"getMacs",                 "()[Ljava/lang/String;",        (void *) getMacs},
        {"getSignAlgorithms",       "()[Ljava/lang/String;",        (void *) getSignAlgorithms},
        {"getPublicKeyEncryptions", "()[Ljava/lang/String;",        (void *) getPublicKeyEncryptions},
        {"getDeriveKeyAlgorithms",  "()[Ljava/lang/String;",        (void *) getDeriveKeyAlgorithms},
        {"generateRandom",          "(I)[B",                        (void *) generateRandom},
        {"getCipherIVLength",       "(Ljava/lang/String;)I",        (void *) getCipherIVLength},
        {"getCipherKeyLength",      "(Ljava/lang/String;)I",        (void *) getCipherKeyLength},
        {"getCipherBlockSize",      "(Ljava/lang/String;)I",        (void *) getCipherBlockSize},
        {"symmetricEncrypt",        "(Ljava/lang/String;[B[B[B)[B", (void *) symmetricEncrypt},
        {"symmetricDecrypt",        "(Ljava/lang/String;[B[B[B)[B", (void *) symmetricDecrypt},
        {"getDigestLength",         "(Ljava/lang/String;)I",        (void *) getDigestLength},
        {"getDigestBlockSize",      "(Ljava/lang/String;)I",        (void *) getDigestBlockSize},
        {"digest",                  "(Ljava/lang/String;[B)[B",     (void *) digest},
//        {"getMacLength",            "(Ljava/lang/String;)[Ljava/lang/String;", (void *) getMacLength},
        {"mac",                     "(Ljava/lang/String;[B[B)[B",   (void *) mac},
//        {"sign",                    "(Ljava/lang/String;[B[B)[B",              (void *) sign},
//        {"verify",                  "(Ljava/lang/String;[B[B[B)I",             (void *) verify},
//        {"publicKeyEncrypt",        "(Ljava/lang/String;[B[B)[B",              (void *) publicKeyEncrypt},
//        {"publicKeyDecrypt",        "(Ljava/lang/String;[B[B)[B",              (void *) publicKeyDecrypt},
//        {"deriveKey",               "(Ljava/lang/String;I[B[B)[B",             (void *) deriveKey},
//        {"getErrorStrings",         "()[Ljava/lang/String;",                   (void *) getErrorStrings},
};


jint registerNativeMethods(JNIEnv *env, const char *class_name, JNINativeMethod *methods,
                           int num_methods) {

    jclass clazz = env->FindClass(class_name);
    if (clazz == NULL) {
        LOGD("registerNativeMethods: class'%s' not found", class_name);
        return JNI_FALSE;
    }

    jint result = env->RegisterNatives(clazz, methods, num_methods);
    if (result < 0) {
        LOGD("registerNativeMethods failed(class=%s)", class_name);
        return JNI_FALSE;
    }

    return result;
}

//回调函数
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {

    LOGD("JNI_OnLoad");

    JNIEnv *env = NULL;
    //获取JNIEnv
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        LOGD("JNI_OnLoad GetEnv fail");
        return -1;
    }
    assert(env != NULL);
    const char *className = "com/megvii/gmlib/GmSSL";
    registerNativeMethods(env, className, methods, NUM_ARRAY_ELEMENTS(methods));

//    const char *classModelName = "com/megvii/actionlib/Model";
//    registerNativeMethods(env, classModelName, modelMethods, NUM_ARRAY_ELEMENTS(modelMethods));

    /*
     * 如果这么写会报JNI_ERR returned from JNI_OnLoad
     *jint result = registerNativeMethods(env, className, methods, NUM_ARRAY_ELEMENTS(methods));
     *if (result == JNI_FALSE) {
     *   return -1;
     *}
     */

    return JNI_VERSION_1_6;
}

