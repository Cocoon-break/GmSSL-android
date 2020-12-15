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

        byte[] data = gmSSL.generateRandom(20);
        for (int i = 0; i < data.length; i++) {
            Log.d(TAG, "data[" + i + "] = " + data[i]);
        }
    }
}