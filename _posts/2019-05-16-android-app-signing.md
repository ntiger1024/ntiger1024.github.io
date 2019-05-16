---
layout: post
title:  "Android 应用签名"
date:   2019-05-16
---

## 官方文档

- [AOSP 关于签名的官方文档](https://source.android.com/security/apksigning)

## V1签名

Android最早支持的签名机制。

V1 签名使用[Java Jar签名机制](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#Signed_JAR_File)。V1签名机制只保护ZIP中的文件项，对ZIP格式中的metadeta等数据没有保护，带来了很多安全问题。另外由于签名校验需要解压所有的内容，额外消耗资源。所以后续引入了V2，V3签名机制。

![V1签名](/images/posts/android_apk_signing/apk_signing.png)

### 实现

使用RSA key "testkey" 签名apk的主要流程

1. 计算每个文件的哈希，base64之后存放到META-INF/MANIFEST.MF文件
2. 计算META-INF/MANIFEST.MF文件的哈希，base64之后存放到META-INF/KEYNAME.SF文件。KEYNAME表示签名所用key的别名
3. 计算META-INF/MANIFEST.MF文件中每个文件哈希的哈希，base64之后存放到META-INF/KEYNAME.SF文件
4. 计算META-INF/KEYNAME.ALG的签名，和证书一起，按照PKCS7格式存放到META-INF/KEYNAME.ALG。ALG表示KEY类型，可以是RSA/DSA/EC等

![V1签名测试](/images/posts/android_apk_signing/apk_signing_openssl.png)

META-INF/KEYNAME.ALG 是pkcs7格式的签名数据，一般包含签名的证书，签名数据等。详细格式参考[RFC5652](https://tools.ietf.org/html/rfc5652)。

## V2签名

从Android 7.0开始支持。

V2签名不再对apk中的每个entry进行签名，而是对整个文件进行签名。签名数据插入到zip文件的Central Directory签名。

![V2签名](/images/posts/android_apk_signing/apk_signing_v2.png)

V2数据结构示意图：

![V2签名](/images/posts/android_apk_signing/apk_sig_v2_struct.png)

注意事项：

- 由于增加APK Signing Block数据会修改End of centroal Directory中的数据，所以在校验的时候，需要先进行恢复。
- 防降级保护：同时使用V1和V2签名的时候，需要在V1签名的*.SF文件中增加X-Android-APK-Signed属性

## V3 signing

从android 9.0开始支持。

V3签名与V2具有相似的结构，增加了Apk key rotation功能，即支持apk更换签名。

限制：不支持多个证书签名。

## Android签名校验流程

![签名校验](/images/posts/android_apk_signing/apk_signing_verify.jpg)

## 常用工具/命令

- 查看V1签名的证书

```shell
# 使用keytool工具
keytool -printcert -jarfile test_v1.apk
```

- apksigner对apk签名

```shell
# 默认V1，V2，V3签名
apksigner sign --in xx_unsigned.apk --out xx.apk --key testkey.pk8 --cert testkey.x509.pem
apksigner sign --in xx_unsigned.apk --out xx.apk --ks test.ks

# 禁用V2/V3签名
apksigner sign --in xx_unsigned.apk --out xx.apk --key testkey.pk8 --cert testkey.x509.pem --v2-signing-enabled false --v3-signing-enabled false
```

- 校验签名/查看签名证书

```shell
apksigner verify -in xx.apk -v
apksigner verify -in xx.apk -v --print-certs
```

- 更换签名

```shell
# 使用platform签名apk
apksigner sign -in test_unsigned.apk -out test_v1.apk -key keys/platform.pk8 -cert keys/platform.x509.pem

# step1: 创建proof-of-rotate结构
apksigner rotate -out platform_share.por -old-signer -key keys/platform.pk8 -cert keys/platform.x509.pem -new-signer -key keys/shared.pk8 -cert keys/shared.x509.pem

# step2: 使用shared签名替换platform签名
apksigner sign -in test_unsigned.apk -out test_v3.apk -lineage platform_share.por -key keys/platform.pk8 -cert keys/platform.x509.pem -next-signer -key keys/shared.pk8 -cert keys/shared.x509.pem

# step3: 更改platform签名apk的权限，这里禁止platform签名的旧apk获取share签名的新apk的权限
apksigner lineage -in platform_share.por -out platform_share.por -signer -key keys/platform.pk8 -cert keys/platform.x509.pem -set-permission false

  # step3.1: 查看修改情况
  apksigner lineage -in platform_share.por -print-certs

# step4: 重新签名，减少platform权限
apksigner sign -in test_unsigned.apk -out test_v4.apk -lineage platform_share.por -key keys/platform.pk8 -cert keys/platform.x509.pem -next-signer -key keys/shared.pk8 -cert keys/shared.x509.pem
```

## CTS 测试

测试ROM是否支持。

```shell
cts-tradefed run singleCommand cts --skip-device-info --skip-preconditions --abi arm64-v8a --module CtsAppSecurityHostTestCases -t android.appsecurity.cts.PkgInstallSignatureVerificationTest
```