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
        String[] versions = gmSSL.getVersions();
        for (int i = 0; i < versions.length; i++) {
            Log.d(TAG, versions[i]);
        }

    }
}