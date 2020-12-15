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

static void list_cipher_fn(const EVP_CIPHER *c,
                           const char *from, const char *to, void *argv) {
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

static void list_md_fn(const EVP_MD *md,
                       const char *from, const char *to, void *argv) {
    STACK_OF(OPENSSL_CSTRING) *sk = static_cast<stack_st_OPENSSL_CSTRING *>(argv);
    if (md) {
        sk_OPENSSL_CSTRING_push(sk, EVP_MD_name(md));
    } else {
        sk_OPENSSL_CSTRING_push(sk, from);
    }
}

JNIEXPORT jobjectArray JNICALL getDigests(
        JNIEnv *env, jclass thiz) {
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

/** jni中定义的JNINativeMethod
 * typedef struct {
    const char* name; //Java方法的名字
    const char* signature; //Java方法的签名信息
    void*       fnPtr; //JNI中对应的方法指针
} JNINativeMethod;
 */
static JNINativeMethod methods[] = {
        {"getVersions", "()[Ljava/lang/String;", (void *) getVersions},
        {"getCiphers",  "()[Ljava/lang/String;", (void *) getCiphers},
        {"getDigests",  "()[Ljava/lang/String;", (void *) getDigests},
//        {"getMacs",                 "()[Ljava/lang/String;",                   (void *) getMacs},
//        {"getSignAlgorithms",       "()[Ljava/lang/String;",                   (void *) getSignAlgorithms},
//        {"getPublicKeyEncryptions", "()[Ljava/lang/String;",                   (void *) getPublicKeyEncryptions},
//        {"getDeriveKeyAlgorithms",  "()[Ljava/lang/String;",                   (void *) getDeriveKeyAlgorithms},
//        {"generateRandom",          "(I)[B",                                   (void *) generateRandom},
//        {"getCipherIVLength",       "(Ljava/lang/String;)I",                   (void *) getCipherIVLength},
//        {"getCipherKeyLength",      "(Ljava/lang/String;)I",                   (void *) getCipherKeyLength},
//        {"getCipherBlockSize",      "(Ljava/lang/String;)I",                   (void *) getCipherBlockSize},
//        {"symmetricEncrypt",        "(Ljava/lang/String;[B[B[B)[B",            (void *) symmetricEncrypt},
//        {"symmetricDecrypt",        "(Ljava/lang/String;[B[B[B)[B",            (void *) symmetricDecrypt},
//        {"getDigestLength",         "(Ljava/lang/String;)I",                   (void *) getDigestLength},
//        {"getDigestBlockSize",      "(Ljava/lang/String;)I",                   (void *) getDigestBlockSize},
//        {"digest",                  "(Ljava/lang/String;[B)[B",                (void *) digest},
//        {"getMacLength",            "(Ljava/lang/String;)[Ljava/lang/String;", (void *) getMacLength},
//        {"mac",                     "(Ljava/lang/String;[B[B)[B",              (void *) mac},
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

