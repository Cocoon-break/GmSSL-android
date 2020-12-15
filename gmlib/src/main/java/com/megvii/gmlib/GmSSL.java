package com.megvii.gmlib;

public class GmSSL {
    public native String[] getVersions();

    public native String[] getCiphers();
//
    public native String[] getDigests();
//
    public native String[] getMacs();
//
    public native String[] getSignAlgorithms();
//
    public native String[] getPublicKeyEncryptions();
//
//    public native String[] getDeriveKeyAlgorithms();
//
//    public native byte[] generateRandom(int length);
//
//    public native int getCipherIVLength(String cipher);
//
//    public native int getCipherKeyLength(String cipher);
//
//    public native int getCipherBlockSize(String cipher);
//
//    public native byte[] symmetricEncrypt(String cipher, byte[] in, byte[] key, byte[] iv);
//
//    public native byte[] symmetricDecrypt(String cipher, byte[] in, byte[] key, byte[] iv);
//
//    public native int getDigestLength(String digest);
//
//    public native int getDigestBlockSize(String digest);
//
//    public native byte[] digest(String algor, byte[] data);
//
//    public native String[] getMacLength(String algor);
//
//    public native byte[] mac(String algor, byte[] data, byte[] key);
//
//    public native byte[] sign(String algor, byte[] data, byte[] privateKey);
//
//    public native int verify(String algor, byte[] digest, byte[] signature, byte[] publicKey);
//
//    public native byte[] publicKeyEncrypt(String algor, byte[] in, byte[] publicKey);
//
//    public native byte[] publicKeyDecrypt(String algor, byte[] in, byte[] privateKey);
//
//    public native byte[] deriveKey(String algor, int keyLength, byte[] peerPublicKey, byte[] privateKey);
//
//    public native String[] getErrorStrings();

    static {
        System.loadLibrary("gmssl");
    }
}
