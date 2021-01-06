## GmSSL-android
[GmSSL](https://github.com/guanzhi/GmSSL) Android下实现。实现SM2/SM3/SM4对数据加密。如果该仓库对你有帮助的话，欢迎start



## Quick Start

1. 使用module 添加到自己的工程中。

   ```shell
   git clone https://github.com/Cocoon-break/GmSSL-android
   cd GmSSL-android
   ```

   将gmlib添加到自己工程中作为依赖module。该方式需要NDK，因为底层是由JNI实现。

2. 直接使用release 中的aar包。

   直接从release中下载aar包，添加到自己工程中。最小支持Android SDK minSdkVersion 21

具体的API使用参考[MainActivity.java](https://github.com/Cocoon-break/GmSSL-android/blob/main/app/src/main/java/com/megvii/gm_android/MainActivity.java)，同时MainActivity.java中也包含了对GBT 35275 数字信封格式的使用，封装该格式使用了bouncycastle 库，具体使用直接看代码即可。



## Developers

如果你想从零开始封装[GmSSL](https://github.com/guanzhi/GmSSL)。

1. 编译armv7和arm64使用的libssl.a和libcrypto.a。

   编译环境和编译脚本参考[more](https://github.com/Cocoon-break/GmSSL-android/blob/main/more.md)

2. JNI封装

   本工程使用JNI是使用的动态注册的方式实现。在我的[RegisterJni](https://github.com/Cocoon-break/RegisterJni)工程中可参考学习。



## Other

本来数字信封和数字签名流程写在[more](https://github.com/Cocoon-break/GmSSL-android/blob/main/more.md)中但是github的markdown不支持mermaid，我就手动截图一份

1. 数字信封流程

   GBT-35275 标准数字信封格式，具体使用参考[MainActivity.java](https://github.com/Cocoon-break/GmSSL-android/blob/main/app/src/main/java/com/megvii/gm_android/MainActivity.java)。

   Server 生成非对称密钥的公钥和私钥:asymmetric_pub_key & asymmetric_pri_key

   ![1.jpg](https://github.com/Cocoon-break/GmSSL-android/blob/main/pics/1.jpg?raw=true)

   1. Client 使用generateRandom(16)，生成对称密钥。symmetric_key
   2. Client 使用symmetricEncrypt()和对称密钥，对明文进行加密。src_symmetric_en
   3. Client 使用publicKeyEncrypt()和Server的公钥，加密**对称密钥**。symmetric_key_en
   4. Client 将加密后的密文和加密后的对称密钥提供给Server端。
   5. Server使用publicKeyDecrypt()和Server的私钥，解密得道对称密钥。symmetric_key
   6. Server使用symmetricDecrypt()和对称密钥，解密密文得到明文。src

   ![2.jpg](https://github.com/Cocoon-break/GmSSL-android/blob/main/pics/2.jpg?raw=true)

2. 数字签名流程

   Server 生成非对称密钥的公钥和私钥:asymmetric_pub_key & asymmetric_pri_key

   ![3.jpg](https://github.com/Cocoon-break/GmSSL-android/blob/main/pics/3.jpg?raw=true)

   1. Client 使用digest()，对src 计算摘要。digest_src
   2. Client 使用sign()和Server公钥，对digest_src进行签名。digest_src_sign
   3. Client 将digest_src_sign 和 src 发送给Server
   4. Server 使用verify() 对digest_src_sign 和 digest_src进行验签。

   ![4.jpg](https://github.com/Cocoon-break/GmSSL-android/blob/main/pics/4.jpg?raw=true)

 ## License

[the Apache 2.0 license](https://github.com/Cocoon-break/GmSSL-android/blob/main/LICENSE)