# 一款用于各类加解密的小工具

支持支持多种常见的加解密方式，包括对称加密（AES、DES）、非对称加密（RSA）、哈希算法（MD5、SHA256、SM3）、编码方式（Base64、Hex、URL、Unicode）以及国密算法（SM2、SM4）。

## 使用方法
python Iwannacrypt.py \<algorithm\> \<mode\> \<data\> [options]

## 参数说明
- \<algorithm\>：选择的加密/解密算法（base64, hex, url, unicode, md5, sha256, sm3, aes, des, rsa, sm2, sm4）。
- \<mode\>：操作模式（encode, decode, encrypt, decrypt）。
- \<data\>：需要加密、解密、编码或解码的数据。
- [options]：
  - --key：加密/解密密钥（AES、DES、SM4 需要）。
  - --iv：AES 初始化向量（AES 需要）。
  - --public_key：RSA 或 SM2 的公钥（加密时需要）。
  - --private_key：RSA 或 SM2 的私钥（解密时需要）。
