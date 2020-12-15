package com.megvii.gm_android;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;

import com.megvii.gmlib.GmSSL;

public class MainActivity extends AppCompatActivity {
    private String TAG = "GmSSL";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        GmSSL gmSSL = new GmSSL();
        // getVersions
        for (String version : gmSSL.getVersions()) {
            Log.d(TAG, "version--->" + version);
        }
        // getCiphers
        for (String cipher : gmSSL.getCiphers()) {
            Log.d(TAG, "cipher--->" + cipher);
        }
        // getDigests
        for (String digest : gmSSL.getDigests()) {
            Log.d(TAG, "digest--->" + digest);
        }
        // getMacs
        for (String mac : gmSSL.getMacs()) {
            Log.d(TAG, "mac--->" + mac);
        }
        // getSignAlgorithms
        for (String signAlgorithm : gmSSL.getSignAlgorithms()) {
            Log.d(TAG, "signAlgorithms--->" + signAlgorithm);
        }

        // getPublicKeyEncryptions
        for (String publicKeyEncryption : gmSSL.getPublicKeyEncryptions()) {
            Log.d(TAG, "publicKeyEncryption--->" + publicKeyEncryption);
        }

        // getDeriveKeyAlgorithms
        for (String deriveKeyAlgorithms : gmSSL.getDeriveKeyAlgorithms()) {
            Log.d(TAG, "deriveKeyAlgorithms--->" + deriveKeyAlgorithms);
        }

        // generateRandom
        byte[] data = gmSSL.generateRandom(20);
        for (int i = 0; i < data.length; i++) {
            Log.d(TAG, "data[" + i + "] = " + data[i]);
        }
        sm4(gmSSL);
        sm3(gmSSL);

        byte[] macTag = gmSSL.mac("HMAC-SM3", "abc".getBytes(), "password".getBytes());
        for (int i = 0; i < macTag.length; i++) {
            Log.d(TAG, "mac--->" + "macTag[" + i + "] = " + macTag[i]);
        }

        sm2(gmSSL);
    }

    private void sm4(GmSSL gmSSL) {
        // getCipherIVLength
        int cipherIVLen = gmSSL.getCipherIVLength("SMS4");
        Log.d(TAG, "getCipherIVLength--->" + cipherIVLen);

        // getCipherKeyLength
        int cipherKeyLen = gmSSL.getCipherKeyLength("SMS4");
        Log.d(TAG, "getCipherKeyLength--->" + cipherKeyLen);

        // getCipherKeyLength
        int cipherBlockSize = gmSSL.getCipherBlockSize("SMS4");
        Log.d(TAG, "getCipherBlockSize--->" + cipherBlockSize);

        // symmetricEncrypt
        byte[] key = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};
        byte[] iv = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};
        byte[] ciphertext = gmSSL.symmetricEncrypt("SMS4", "01234567".getBytes(), key, iv);
        for (int i = 0; i < ciphertext.length; i++) {
            Log.d(TAG, "symmetricEncrypt--->" + "ciphertext[" + i + "] = " + ciphertext[i]);
        }

        // symmetricDecrypt
        byte[] plaintext = gmSSL.symmetricDecrypt("sms4", ciphertext, key, iv);
        for (int i = 0; i < plaintext.length; i++) {
            Log.d(TAG, "symmetricDecrypt--->" + "plaintext[" + i + "] = " + plaintext[i]);
        }
    }

    private void sm3(GmSSL gmSSL) {
        int digestLen = gmSSL.getDigestLength("SM3");
        Log.d(TAG, "getDigestLength--->" + digestLen);
        int digestBlockSize = gmSSL.getDigestBlockSize("SM3");
        Log.d(TAG, "getDigestBlockSize--->" + digestBlockSize);

        byte[] dgst = gmSSL.digest("SM3", "abc".getBytes());
        for (int i = 0; i < dgst.length; i++) {
            Log.d(TAG, "digest--->" + "dgst[" + i + "] = " + dgst[i]);
        }
    }

    private void sm2(GmSSL gmSSL) {
        byte[] sm2PrivateKey = new byte[]{
                (byte) 0x30, (byte) 0x77, (byte) 0x02, (byte) 0x01, (byte) 0x01, (byte) 0x04, (byte) 0x20, (byte) 0x28,
                (byte) 0x7d, (byte) 0x3f, (byte) 0xb9, (byte) 0xf4, (byte) 0xbb, (byte) 0xc8, (byte) 0xbd, (byte) 0xe1,
                (byte) 0x54, (byte) 0x75, (byte) 0x87, (byte) 0x9f, (byte) 0x08, (byte) 0x61, (byte) 0x20, (byte) 0xe3,
                (byte) 0x65, (byte) 0xf8, (byte) 0xb2, (byte) 0xca, (byte) 0x14, (byte) 0x26, (byte) 0x81, (byte) 0xf6,
                (byte) 0x1e, (byte) 0xd8, (byte) 0x7f, (byte) 0xc0, (byte) 0x66, (byte) 0x20, (byte) 0x29, (byte) 0xa0,
                (byte) 0x0a, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x81, (byte) 0x1c, (byte) 0xcf, (byte) 0x55,
                (byte) 0x01, (byte) 0x82, (byte) 0x2d, (byte) 0xa1, (byte) 0x44, (byte) 0x03, (byte) 0x42, (byte) 0x00,
                (byte) 0x04, (byte) 0xb1, (byte) 0x1e, (byte) 0x4c, (byte) 0x8c, (byte) 0xa9, (byte) 0x02, (byte) 0xf2,
                (byte) 0x8d, (byte) 0x8b, (byte) 0x98, (byte) 0xd2, (byte) 0xd0, (byte) 0xc4, (byte) 0xf1, (byte) 0x60,
                (byte) 0x91, (byte) 0xfb, (byte) 0x61, (byte) 0x62, (byte) 0x00, (byte) 0xcf, (byte) 0x93, (byte) 0x4e,
                (byte) 0x3f, (byte) 0xca, (byte) 0xfd, (byte) 0xf7, (byte) 0x9d, (byte) 0x76, (byte) 0xb8, (byte) 0x2b,
                (byte) 0xb3, (byte) 0x30, (byte) 0x98, (byte) 0x65, (byte) 0xf5, (byte) 0x12, (byte) 0xab, (byte) 0x45,
                (byte) 0x78, (byte) 0x29, (byte) 0x87, (byte) 0xdc, (byte) 0x74, (byte) 0x07, (byte) 0x75, (byte) 0xd0,
                (byte) 0x68, (byte) 0xad, (byte) 0x85, (byte) 0x71, (byte) 0x08, (byte) 0xc2, (byte) 0x19, (byte) 0xf0,
                (byte) 0xf4, (byte) 0xca, (byte) 0x6e, (byte) 0xe1, (byte) 0xea, (byte) 0x86, (byte) 0xe6, (byte) 0x21,
                (byte) 0x76};

        byte[] dgst = gmSSL.digest("SM3", "abc".getBytes());
        byte[] sign = gmSSL.sign("sm2sign", dgst, sm2PrivateKey);
        for (int i = 0; i < sign.length; i++) {
            Log.d(TAG, "sign--->" + "sign[" + i + "] = " + sign[i]);
        }
    }
}