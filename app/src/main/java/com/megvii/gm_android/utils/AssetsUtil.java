package com.megvii.gm_android.utils;

import android.content.Context;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class AssetsUtil {
    public enum PemName {
        PRIVATE_KEY_PEM("private_key.pem"), PUBLIC_KEY_PEM("public_key.pem");
        private String name;

        private PemName(String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }

    }

    public static String readPemContent(PemName penName, Context context) {
        String content = "";
        try {
            InputStream is = context.getAssets().open(penName.getName());

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            int len = -1;
            byte[] buffer = new byte[1024];
            while ((len = is.read(buffer)) != -1) {
                baos.write(buffer, 0, len);
            }
            content = baos.toString();
            is.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        String pemBody = content
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PUBLIC KEY-----", "");
        return pemBody;
    }
}
