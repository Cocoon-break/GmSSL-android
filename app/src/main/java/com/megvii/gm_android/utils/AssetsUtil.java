package com.megvii.gm_android.utils;

import android.content.Context;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class AssetsUtil {
    private static String PUB_BEGIN = "-----BEGIN PUBLIC KEY-----";
    private static String PUB_END = "-----END PUBLIC KEY-----";
    private static String PRI_BEGIN = "-----BEGIN PRIVATE KEY-----";
    private static String PRI_END = "-----END PRIVATE KEY-----";

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

    public static String readPemContent(PemName pemName, Context context) {
        String content = "";
        try {
            InputStream is = context.getAssets().open(pemName.getName());

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
            return "";
        }
        String beginFlag = PUB_BEGIN;
        String endFlag = PUB_END;
        if (pemName == PemName.PRIVATE_KEY_PEM) {
            beginFlag = PRI_BEGIN;
            endFlag = PRI_END;
        }
        String pemBody = content
                .replace(beginFlag, "")
                .replaceAll(System.lineSeparator(), "")
                .replace(endFlag, "");
        return pemBody;
    }
}
