package com.megvii.gm_android;

import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import android.Manifest;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Toast;

import com.megvii.gm_android.envelop.EncryptedContentInfo;
import com.megvii.gm_android.envelop.EnvelopData;
import com.megvii.gm_android.envelop.RecipientInfo;
import com.megvii.gm_android.utils.AssetsUtil;
import com.megvii.gm_android.utils.FileUtils;
import com.megvii.gm_android.utils.TransformUtil;
import com.megvii.gmlib.GmSSL;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.util.ASN1Dump;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import static android.os.Build.VERSION_CODES.M;

public class MainActivity extends Activity {
    private String TAG = "GmSSL";

    private String szPublicKey = "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgciJLxRTdSD9yro2l/eRJEHAlHGUnq2aMAaiJjvNLgdehRANCAAR4adLC8MCYy9Vk6eaiTrTgYnYJf7yQjV/9FMp3o3BxI3KT5KbuUglyhUkHDdUXxsMeRASSbLswV0+GsAmJV+um";


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        findViewById(R.id.tv_start).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                requestCameraPerm();
            }
        });

//        GmSSL gmSSL = new GmSSL();
//        getMessage(gmSSL);
//        sm4(gmSSL);
//        sm3(gmSSL);

//        byte[] macTag = gmSSL.mac("HMAC-SM3", "abc".getBytes(), "password".getBytes());
//        for (int i = 0; i < macTag.length; i++) {
//            Log.d(TAG, "mac--->" + "macTag[" + i + "] = " + macTag[i]);
//        }

//        sm2withSM3(gmSSL);
//        digitalEnvelope(gmSSL);
//        testPem(gmSSL);

    }

    public void startEnvelopedData() {
        // 清除上次记录
        FileUtils.deleteGmsslResult();


        try {
            InputStream inputStream = new FileInputStream("/sdcard/gmssl/luyf.jpg");
            byte[] byteArray = FileUtils.readStream(inputStream);

            GmSSL gmSSL = new GmSSL();
            envelopedData(gmSSL, byteArray);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

//        BitmapFactory.Options bfoOptions = new BitmapFactory.Options();
//        bfoOptions.inScaled = false;
//        Bitmap image = BitmapFactory.decodeFile("/sdcard/gmssl/hxm.jpg", bfoOptions);
//
//        ByteArrayOutputStream stream = new ByteArrayOutputStream();
//        image.compress(Bitmap.CompressFormat.JPEG, 100, stream);
//        byte[] byteArray = stream.toByteArray();
//        image.recycle();


    }

    public void envelopedData(GmSSL gmSSL, byte[] imgData) {
        EnvelopData envelopData = new EnvelopData();
        envelopData.setVersion(1);

        byte[] key = gmSSL.generateRandom(16);
//        Log.d(TAG,"sm4 key hexStr --->"+TransformUtil.byteArrayToHexString(key));
        FileUtils.saveGmssl("sm4 key hexStr --->" + TransformUtil.byteArrayToHexString(key), FileUtils.ENVELOP_PROCESS);
        byte[] cipher = gmSSL.symmetricEncrypt("SMS4", imgData, key, key);
        FileUtils.saveGmssl("sm4 cipher hexStr --->" + TransformUtil.byteArrayToHexString(cipher), FileUtils.ENVELOP_PROCESS);
        EncryptedContentInfo encryptedContentInfo = new EncryptedContentInfo();
        encryptedContentInfo.setEncryptionContent(cipher);
        envelopData.setEncryptedContent(encryptedContentInfo);

        X509Certificate cert = AssetsUtil.readCertificate("custCert.cer", this);
        if (cert != null) {
            BigInteger serialNumber = cert.getSerialNumber();
            String[] issuerDN = cert.getIssuerDN().getName().split(",");
            String countryName = issuerDN[2].replace("C=", "");
            String organizationName = issuerDN[1].replace("O=", "");
            String commonName = issuerDN[0].replace("CN=", "");
            RecipientInfo.IssuerAndSerialNumber issuerAndSerialNumber = new RecipientInfo.IssuerAndSerialNumber(serialNumber, countryName, organizationName, commonName);

            PublicKey publicKey = cert.getPublicKey();
            byte[] sm2Cipher = gmSSL.publicKeyEncrypt("sm2encrypt-with-sm3", key, publicKey.getEncoded());
            Log.d(TAG, "sm2Cipher length:" + sm2Cipher.length);
            FileUtils.saveGmssl("sm2 cipher hexStr --->" + TransformUtil.byteArrayToHexString(sm2Cipher), FileUtils.ENVELOP_PROCESS);
            RecipientInfo info = new RecipientInfo();
            info.setVersion(1);
            info.setIssue(issuerAndSerialNumber);
            info.setEncryptedKey(sm2Cipher);

            envelopData.setRecipientInfo(info);
            try {
                byte[] enData = envelopData.getEncoded();
                String hexStr = TransformUtil.byteArrayToHexString(enData);
                FileUtils.saveGmssl("envelopedData hexStr --->" + hexStr, FileUtils.ENVELOP_PROCESS);
                FileUtils.saveGmssl(hexStr, FileUtils.ENVELOP_RESULT);
                dumpAsN1(hexStr);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void dumpAsN1(String hexStr) {
        byte[] data = TransformUtil.hexStringToByteArray(hexStr);
        ASN1InputStream bIn = new ASN1InputStream(new ByteArrayInputStream(data));
        ASN1Primitive obj = null;
        try {
            obj = bIn.readObject();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println(ASN1Dump.dumpAsString(obj));
    }

    private void getMessage(GmSSL gmSSL) {
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
//        byte[] key = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};
//        byte[] iv = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};
        byte[] key_iv = gmSSL.generateRandom(16);
        String src = "01234567";
        // SMS4 就是sms4-ecb
        byte[] ciphertext = gmSSL.symmetricEncrypt("SMS4", src.getBytes(), key_iv, key_iv);
        Log.d(TAG, "symmetricEncrypt--->HexString: " + TransformUtil.byteArrayToHexString(ciphertext));

        // symmetricDecrypt
        byte[] plaintext = gmSSL.symmetricDecrypt("SMS4", ciphertext, key_iv, key_iv);
        Log.d(TAG, "symmetricDecrypt--->" + TransformUtil.byteArrayToUTF8String(plaintext));
    }

    private void sm3(GmSSL gmSSL) {
        int digestLen = gmSSL.getDigestLength("SM3");
        Log.d(TAG, "getDigestLength--->" + digestLen);
        int digestBlockSize = gmSSL.getDigestBlockSize("SM3");
        Log.d(TAG, "getDigestBlockSize--->" + digestBlockSize);

        byte[] dgst = gmSSL.digest("SM3", "abc".getBytes());
        Log.d(TAG, "digest--->" + TransformUtil.byteArrayToHexString(dgst));
//        for (int i = 0; i < dgst.length; i++) {
//            Log.d(TAG, "digest--->" + "dgst[" + i + "] = " + dgst[i]);
//        }
    }

    private byte[] sm2PrivateKey = new byte[]{
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

    private byte[] sm2PublicKey = new byte[]{
            (byte) 0x30, (byte) 0x59, (byte) 0x30, (byte) 0x13, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86,
            (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x02, (byte) 0x01, (byte) 0x06, (byte) 0x08, (byte) 0x2a,
            (byte) 0x81, (byte) 0x1c, (byte) 0xcf, (byte) 0x55, (byte) 0x01, (byte) 0x82, (byte) 0x2d, (byte) 0x03,
            (byte) 0x42, (byte) 0x00, (byte) 0x04, (byte) 0xb1, (byte) 0x1e, (byte) 0x4c, (byte) 0x8c, (byte) 0xa9,
            (byte) 0x02, (byte) 0xf2, (byte) 0x8d, (byte) 0x8b, (byte) 0x98, (byte) 0xd2, (byte) 0xd0, (byte) 0xc4,
            (byte) 0xf1, (byte) 0x60, (byte) 0x91, (byte) 0xfb, (byte) 0x61, (byte) 0x62, (byte) 0x00, (byte) 0xcf,
            (byte) 0x93, (byte) 0x4e, (byte) 0x3f, (byte) 0xca, (byte) 0xfd, (byte) 0xf7, (byte) 0x9d, (byte) 0x76,
            (byte) 0xb8, (byte) 0x2b, (byte) 0xb3, (byte) 0x30, (byte) 0x98, (byte) 0x65, (byte) 0xf5, (byte) 0x12,
            (byte) 0xab, (byte) 0x45, (byte) 0x78, (byte) 0x29, (byte) 0x87, (byte) 0xdc, (byte) 0x74, (byte) 0x07,
            (byte) 0x75, (byte) 0xd0, (byte) 0x68, (byte) 0xad, (byte) 0x85, (byte) 0x71, (byte) 0x08, (byte) 0xc2,
            (byte) 0x19, (byte) 0xf0, (byte) 0xf4, (byte) 0xca, (byte) 0x6e, (byte) 0xe1, (byte) 0xea, (byte) 0x86,
            (byte) 0xe6, (byte) 0x21, (byte) 0x76};

    private void sm2withSM3(GmSSL gmSSL) {
        String src = "abc";
        byte[] dgst = gmSSL.digest("SM3", src.getBytes());
        String hexDgst = TransformUtil.byteArrayToHexString(dgst);
        Log.d(TAG, "digest--->" + hexDgst);
        byte[] sign = gmSSL.sign("sm2sign", dgst, sm2PrivateKey);
        Log.d(TAG, "sign--->" + TransformUtil.byteArrayToHexString(sign));
//        for (int i = 0; i < sign.length; i++) {
//            Log.d(TAG, "sign--->" + "sign[" + i + "] = " + sign[i]);
//        }

        int vret = gmSSL.verify("sm2sign", dgst, sign, sm2PublicKey);
        Log.d(TAG, "sign--->" + (vret == 1));

        byte[] sm2Ciphertext = gmSSL.publicKeyEncrypt("sm2encrypt-with-sm3", dgst, sm2PublicKey);
        Log.d(TAG, "publicKeyEncrypt--->" + TransformUtil.byteArrayToHexString(sm2Ciphertext));
//        for (int i = 0; i < sm2Ciphertext.length; i++) {
//            Log.d(TAG, "publicKeyEncrypt--->" + "sm2Ciphertext[" + i + "] = " + sm2Ciphertext[i]);
//        }

        byte[] sm2Plaintext = gmSSL.publicKeyDecrypt("sm2encrypt-with-sm3", sm2Ciphertext, sm2PrivateKey);
        String hexSm2Plaintext = TransformUtil.byteArrayToHexString(sm2Plaintext);
        Log.d(TAG, "publicKeyDecrypt--->" + hexSm2Plaintext);
        Log.d(TAG, "publicKeyDecrypt---> ok?= " + hexSm2Plaintext.equals(hexDgst));
//        for (int i = 0; i < sm2Plaintext.length; i++) {
//            Log.d(TAG, "publicKeyDecrypt--->" + "sm2Plaintext[" + i + "] = " + sm2Plaintext[i]);
//        }

    }

    // 数字信封流程
    private void digitalEnvelope(GmSSL gmSSL) {
        // 1. A生成一随机的对称密钥，即会话密钥
        byte[] key_iv = gmSSL.generateRandom(16);
        String src = "abc";
        // 2. A用会话密钥加密明文
        byte[] ciphertext = gmSSL.symmetricEncrypt("SMS4", src.getBytes(), key_iv, key_iv);
        // 3. A用B的公钥加密会话密钥
        String publicPem = AssetsUtil.readPemContent(AssetsUtil.PemName.PUBLIC_KEY_PEM, this);
        byte[] sm2PublicKey = Base64.decode(publicPem, Base64.DEFAULT);
        byte[] sm2Ciphertext = gmSSL.publicKeyEncrypt("sm2encrypt-with-sm3", key_iv, sm2PublicKey);

        //4. B使用自己的私钥解密会话密钥。
        String privatePem = AssetsUtil.readPemContent(AssetsUtil.PemName.PRIVATE_KEY_PEM, this);
        byte[] sm2PrivateKey = Base64.decode(privatePem, Base64.DEFAULT);
        byte[] key_iv_d = gmSSL.publicKeyDecrypt("sm2encrypt-with-sm3", sm2Ciphertext, sm2PrivateKey);

        //5. B使用会话密钥解密密文，得到明文
        byte[] result = gmSSL.symmetricDecrypt("SMS4", ciphertext, key_iv_d, key_iv_d);
        Log.d(TAG, "symmetricDecrypt--->" + TransformUtil.byteArrayToUTF8String(result));
    }

    private void testPem(GmSSL gmSSL) {
        // 1. A生成一随机的对称密钥，即会话密钥
        byte[] key_iv = gmSSL.generateRandom(16);
        String src = "abc";
        // 2. A用会话密钥加密明文
        byte[] ciphertext = gmSSL.symmetricEncrypt("SMS4", src.getBytes(), key_iv, key_iv);
        // 3. A用B的公钥加密会话密钥
//        String publicPem = AssetsUtil.readPemContent(AssetsUtil.PemName.CER_KEY_PEM, this);
        byte[] sm2PublicKey = AssetsUtil.readCerContent("yisuo.cer", this);

        byte[] sm2Ciphertext = gmSSL.publicKeyEncrypt("sm2encrypt-with-sm3", key_iv, sm2PublicKey);
        if (sm2Ciphertext != null && sm2Ciphertext.length > 0) {
            Log.d(TAG, "testPem ---> ok");
        } else {
            Log.d(TAG, "testPem ---> fail");
        }

    }

    private void requestCameraPerm() {
        if (android.os.Build.VERSION.SDK_INT >= M) {
            if (ContextCompat.checkSelfPermission(this,
                    Manifest.permission.WRITE_EXTERNAL_STORAGE)
                    != PackageManager.PERMISSION_GRANTED) {
                //进行权限请求
                ActivityCompat.requestPermissions(this,
                        new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE},
                        EXTERNAL_STORAGE_REQ_CAMERA_CODE);
            } else {
                startEnvelopedData();
            }
        } else {
            startEnvelopedData();
        }
    }

    public static final int EXTERNAL_STORAGE_REQ_CAMERA_CODE = 10;


    @Override
    public void onRequestPermissionsResult(int requestCode,
                                           String permissions[], int[] grantResults) {
        if (requestCode == EXTERNAL_STORAGE_REQ_CAMERA_CODE) {
            if (grantResults[0] != PackageManager.PERMISSION_GRANTED) {// Permission Granted
                Toast.makeText(this, "无读写权限", Toast.LENGTH_LONG).show();
            } else {
                startEnvelopedData();
            }
        }
    }

}