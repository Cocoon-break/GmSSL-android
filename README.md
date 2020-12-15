### env
android studio 4.0.1
java version "1.8.0_261"
ndk 21.3.6528147



### build GmSSL

默认openssl/opensslconf.h.in Cmake是无法直接编译通过的，可通过编译静态库获取。

```shell
git clone https://github.com/guanzhi/GmSSL
cd GmSSL
mkdir build && cd build
./build_android_v7a
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

编译结束获取。libcrypto.a , libssl.a 和 opensslconf.h

reference: https://github.com/guanzhi/GmSSL/tree/master/java