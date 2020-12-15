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
}