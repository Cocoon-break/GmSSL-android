### ENV
android studio 4.0.1

java version "1.8.0_261"

ndk version 21.3.6528147

### build GmSSL

默认openssl/opensslconf.h.in Cmake是无法直接编译通过的，可通过编译静态库获取。

```shell
git clone https://github.com/guanzhi/GmSSL
cd GmSSL
mkdir build && cd build
./build_android_v7a.sh
cd ..
mkdir build64 && cd build64
./build_android_arm64.sh
```

build_android_v7a.sh 只是32位。参考[编译与安装](http://gmssl.org/docs/install.html)

```shell
#!/bin/bash

ANDROID_PATH=/Users/wushengping/Library/Android
PLATFORM_VERSION=22

MAKE_TOOLCHAIN=$ANDROID_PATH/sdk/ndk/21.3.6528147/build/tools/make-standalone-toolchain.sh
export TOOLCHAIN_PATH=$ANDROID_PATH/android-toolchain-arm
$MAKE_TOOLCHAIN --arch=arm --platform=android-$PLATFORM_VERSION --install-dir=$TOOLCHAIN_PATH

export MACHINE=armv7
export SYSTEM=android
export ARCH=arm
export CROSS_SYSROOT=$TOOLCHAIN_PATH/sysroot
export TOOL_BASENAME=$TOOLCHAIN_PATH/bin/arm-linux-androideabi
export CC=$TOOL_BASENAME-gcc
export CXX=$TOOL_BASENAME-g++
export LD=$TOOL_BASENAME-ld
export LINK=$CXX
export AR=$TOOL_BASENAME-ar
export RANLIB=$TOOL_BASENAME-ranlib
export STRIP=$TOOL_BASENAME-strip

../config
make
```

build_android_arm64.sh 是64位的。参考[Gmssl 各平台编译方法](https://blog.csdn.net/qq_19734597/article/details/103264132)

```shell
#!/bin/bash

ANDROID_PATH=/Users/wushengping/Library/Android
PLATFORM_VERSION=22

MAKE_TOOLCHAIN=$ANDROID_PATH/sdk/ndk/21.3.6528147/build/tools/make-standalone-toolchain.sh
export TOOLCHAIN_PATH=$ANDROID_PATH/aarch64-linux-android
$MAKE_TOOLCHAIN --arch=arm64 --platform=android-$PLATFORM_VERSION --install-dir=$TOOLCHAIN_PATH

export MACHINE=armv8
export SYSTEM=android-v8
export ARCH=arm64
export CROSS_SYSROOT=$TOOLCHAIN_PATH/sysroot
export TOOL_BASENAME=$TOOLCHAIN_PATH/bin/aarch64-linux-android
export CC=$TOOL_BASENAME-gcc
export CXX=$TOOL_BASENAME-g++
export LD=$TOOL_BASENAME-ld
export LINK=$CXX
export AR=$TOOL_BASENAME-ar
export RANLIB=$TOOL_BASENAME-ranlib
export STRIP=$TOOL_BASENAME-strip

../config
make
```

编译结束获取build和build64文件夹下的libcrypto.a , libssl.a 和 opensslconf.h

### 生成公私钥Pem

1. 生成私钥

   ```shell
   openssl ecparam -genkey -name SM2 -out sm2_private_key.pem
   ```

2. 私钥转换pkcs8

   ```shell
   openssl pkcs8 -topk8 -inform PEM -in sm2_private_key.pem -outform pem -nocrypt -out private_key.pem
   ```

3. 生产公钥

   ```shell
   openssl ec -in sm2_private_key.pem -pubout -out public_key.pem
   ```

生成证书可以参考[GMCA 仓库](https://github.com/ziyaofeng/GMCA)

### 数字信封和数字签名流程

#### 数字信封

##### 1. 流程

Client 生成对称密钥:symmetric_key

Server 生成非对称密钥的公钥和私钥:asymmetric_pub_key & asymmetric_pri_key

```mermaid
graph TB
A(Client) -->B(symmetric_key)
C(Server) -->D(asymmetric_pub_key)
C(Server) -->E(asymmetric_pri_key)
```
1. Client 使用generateRandom(16)，生成对称密钥。symmetric_key

2. Client 使用symmetricEncrypt()和对称密钥，对明文进行加密。src_symmetric_en

3. Client 使用publicKeyEncrypt()和Server的公钥，加密**对称密钥**。symmetric_key_en

4. Client 将加密后的密文和加密后的对称密钥提供给Server端。

5. Server使用publicKeyDecrypt()和Server的私钥，解密得道对称密钥。symmetric_key

6. Server使用symmetricDecrypt()和对称密钥，解密密文得到明文。src

```mermaid
sequenceDiagram
    autonumber
    Client->>Client: generate symmetric_key
    Client->>Client: src symmetricEncrypt-->src_symmetric_en
    Client->>Client: symmetric_key publicKeyEncrypt-->symmetric_key_en
    Client->>Server: src_symmetric_en and symmetric_key_en
    Server->>Server: publicKeyDecrypt symmetric_key_en --> symmetric_key
    Server->>Server: symmetricDecrypt src_symmetric_en --> src
```

##### 2. 格式

主要用是GBT 35275 标准，数字信封本质上是ASN.1 格式编码，由于没有其他现成的ASN.1 的库，就直接使用了bouncycastle库。根据标准封装了相关类和使用方法已经在[MainActivity.java](https://github.com/Cocoon-break/GmSSL-android/blob/main/app/src/main/java/com/megvii/gm_android/MainActivity.java)体现了。

[GBT 35275 标准文档](https://github.com/Cocoon-break/GmSSL-android/blob/main/GBT-35275-2017.pdf)

[ASN.1 在线解析库](https://lapo.it/asn1js/)

以下文本可以在[ASN.1 在线解析库](https://lapo.it/asn1js/)解析出数字信封格式。

```shell
30820114060A2A811CCF550601040203A0820104308201000201013181CF3081CC020101303D3031310B300906035504061302434E3111300F060355040A1308474C435449443031310F300D06035504031306474C434130310208549EAD2894BF7D84300B06092A811CCF5501822D03047B3079022100DDAEC4AB2F96AC7CFED7B35392466FD1F71365D3904D51C0AA81A5777272A7F0022042B1B060FA41530E030B39F99610F1E90F8A59DAD400E15008B0FB7CB68886120420D33A3BD05011A74D0C1C7F449EE77D1DDBFCED67A37229AB5D6F0813EE04F98F04106F237DB2FF966D7062F4E45C9EE562CF3029060A2A811CCF550601040201300906072A811CCF55016880104BA75C32AD66CC92B14DC7F0ADF970DA
```



#### 数字签名流程

Server 生成非对称密钥的公钥和私钥:asymmetric_pub_key & asymmetric_pri_key
```mermaid
graph TB
C(Server) -->D(asymmetric_pub_key)
C(Server) -->E(asymmetric_pri_key)
```
1. Client 使用digest()，对src 计算摘要。digest_src
2. Client 使用sign()和Server公钥，对digest_src进行签名。digest_src_sign
3. Client 将digest_src_sign 和 src 发送给Server
4. Server 使用verify() 对digest_src_sign 和 digest_src进行验签。

```mermaid
sequenceDiagram
    autonumber
    Client->>Client: digest src-->digest_src
    Client->>Client: digest_src sign-->digest_src_sign
    Client->>Server: src and digest_src_sign
    Server->>Server: verify src and digest_src_sign
```


