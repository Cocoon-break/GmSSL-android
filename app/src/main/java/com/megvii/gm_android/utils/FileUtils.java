package com.megvii.gm_android.utils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

public class FileUtils {
    private static String BASE_DIR = "/sdcard/gmssl";
    public static String ENVELOP_PROCESS = "enveloped_process.txt";
    public static String ENVELOP_RESULT = "envelopedData.txt";

    public static void deleteGmsslResult() {
        String dirPath = BASE_DIR;
        File dir = new File(dirPath);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        File file = new File(dir, ENVELOP_PROCESS);
        if (file.exists()) {
            file.delete();
        }
        File file2 = new File(dir, ENVELOP_RESULT);
        if (file2.exists()) {
            file2.delete();
        }
    }

    public static boolean saveGmssl(String content, String fileName) {
        try {
            String dirPath = BASE_DIR;
            File dir = new File(dirPath);
            if (!dir.exists()) {
                dir.mkdirs();
            }
            String body = content + "\n";
            File file = new File(dir, fileName);
            FileOutputStream fileOutputStream = new FileOutputStream(file, true);
            fileOutputStream.write(body.getBytes());
            fileOutputStream.flush();
            fileOutputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }


    public static byte[] readStream(InputStream inStream) throws Exception {
        byte[] buffer = new byte[1024];
        int len = -1;
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        while ((len = inStream.read(buffer)) != -1) {
            outStream.write(buffer, 0, len);
        }
        byte[] data = outStream.toByteArray();
        outStream.close();
        inStream.close();
        return data;
    }
}
