package com.megvii.gm_android.utils;

import android.content.Context;
import android.content.res.AssetManager;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

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
    public static String copyAssets(Context context, String filename) {
        AssetManager assetManager = context.getAssets();
        InputStream in = null;
        OutputStream out = null;
        try {
            in = assetManager.open(filename);
            String dirPath = BASE_DIR;
            File dir = new File(dirPath);
            if (!dir.exists()) {
                dir.mkdirs();
            }
            File outFile = new File(dir, filename);
            if (outFile.exists()) {
                return outFile.getAbsolutePath();
            }
            out = new FileOutputStream(outFile);
            copyFile(in, out);
            return outFile.getAbsolutePath();
        } catch (IOException e) {
            e.printStackTrace();
            return "";
        } finally {
            try {
                if (in != null) {
                    in.close();
                }
                if (out != null) {
                    out.close();

                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private static void copyFile(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[1024];
        int read;
        while ((read = in.read(buffer)) != -1) {
            out.write(buffer, 0, read);
        }
    }
}
