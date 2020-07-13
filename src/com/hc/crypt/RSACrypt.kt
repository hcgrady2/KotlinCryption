package com.hc.crypt

import java.io.ByteArrayOutputStream
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

object RSACrypt {

    val transformation = "RSA"
    val encrypt_max_size = 117   //加密是 117
    val DECRYPT_MAX_SIZE = 128   //解密是 128



    val publicKeyStr  = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCRa7yJsaO4mb/xaJZvoWYWUzUiQm2858uk6eyXKOtk1qOeMks5U26nnAn4VaEYuJTUkk+pZSsPMGgwuSvFzytts0GmHybj6bEGQR/ZKJSaMDCwdoH4LBPdBOaES0ZdLyVUpgW/QWhS+hjZA5roS3TNr8fA627Frm60257OXUoWmQIDAQAB"
    val privateKeyStr  = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJFrvImxo7iZv/Folm+hZhZTNSJCbbzny6Tp7Jco62TWo54ySzlTbqecCfhVoRi4lNSST6llKw8waDC5K8XPK22zQaYfJuPpsQZBH9kolJowMLB2gfgsE90E5oRLRl0vJVSmBb9BaFL6GNkDmuhLdM2vx8DrbsWubrTbns5dShaZAgMBAAECgYASj6rP9HGORWmfeZcCBprOLK6ygcIaA4gVs5n0LU/mXhMiRQ8e8QxFroADR4K5cg3lGAu89mHJnYce+POiWvAS7ZcEH1P5P5UIDsy/k5HNyRG6jQYLkmB4DZ3h20woO2JfL2AYqbDIbKVK0HprgGaN0X9kkaA14NUZkkeXIC070QJBAOIhzv+ajCntmjzbt3xFdjhZ2yQv5L0VoX3LOgdWfYzAanMuaFxGPDNFQvo0gFnDEUx9zqrn2BR/8+MBQlmr1NUCQQCkoNgADdcLIbkU+1BVgWGEHGBkc0sWuxMoqmDoGEjs1aQ3NXmq2Z2qKNV8N8wVvmYs9fe6w9g9FOd9VrexWCy1AkEAh/008toKOJy/CKJJcd6D/ddrxhNXR67eczvoJcmJrz93xNS/xd4nDd41LSqtlU2N9aYixvyuIYXhMT7sm+iOEQJBAKLtfFgxWk3uBho5znuRHE1/N/ayE/JfGsr4NAf/YMzjcy4gglUQIfWxi/bv0c8DLGP62j3AbVWmRqPJGuss9LECQHDsYLWZL1tuQ3Gc+HvDS1yKjV9sqI0G8Ewqq88LWT0vQWbNT8yN/2yWAhvQQNX6Uem3BdkAvChAdxsGIKS1Dsg="


    fun encryptByPrivateKey(input: String, privateKey: PrivateKey): String {
        //密钥对生成器
//        val keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//        //生成密钥对
//        val keyPair  = keyPairGenerator.genKeyPair();
//        val publicKey = keyPair.public
//        val privateKey = keyPair.private

        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.ENCRYPT_MODE, privateKey)

        //分段加密
        val byteArray = input.toByteArray()
        var temp: ByteArray? = null  //缓存
        var offset = 0  //当前偏移

        val bos = ByteArrayOutputStream()

        while (byteArray.size - offset > 0) {
            //判断是否是最后一块
            if (byteArray.size - offset >= encrypt_max_size) {
                temp = cipher.doFinal(byteArray, offset, encrypt_max_size)
                offset += encrypt_max_size
            } else {
                temp = cipher.doFinal(byteArray, offset, byteArray.size - offset)
                offset += byteArray.size
            }
            bos.write(temp)
        }
        bos.close()
        return Base64Util.encode(bos.toByteArray())
    }

    fun encryptByPublicKey(input: String, publicKey: PublicKey): String {
//        //密钥对生成器
//        val keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//        //生成密钥对
//        val keyPair  = keyPairGenerator.genKeyPair();
//        val publicKey = keyPair.public
//        val privateKey = keyPair.private


//        var key:Key ?= null
//
//        val cipher = Cipher.getInstance(transformation)
//        cipher.init(Cipher.ENCRYPT_MODE,publicKey)
//        val  encrypy = cipher.doFinal(input.toByteArray())
//
//        return Base64Util.encode(encrypy)


        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)

        //分段加密
        val byteArray = input.toByteArray()
        var temp: ByteArray? = null  //缓存
        var offset = 0  //当前偏移

        val bos = ByteArrayOutputStream()

        while (byteArray.size - offset > 0) {
            //判断是否是最后一块
            if (byteArray.size - offset >= encrypt_max_size) {
                temp = cipher.doFinal(byteArray, offset, encrypt_max_size)
                offset += encrypt_max_size
            } else {
                temp = cipher.doFinal(byteArray, offset, byteArray.size - offset)
                offset = byteArray.size
            }
            bos.write(temp)
        }

        bos.close()

        return Base64Util.encode(bos.toByteArray())
    }


    /**
     * 私钥解密
     */
    fun decryptByPrivateKey(input: String, privateKey: PrivateKey): String {
        //密钥对生成器
//        val keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//        //生成密钥对
//        val keyPair  = keyPairGenerator.genKeyPair();
//        val publicKey = keyPair.public
//        val privateKey = keyPair.private

        //先解码
        // val byteArray = Base64Util.decode(input)
        val byteArray = Base64.getDecoder().decode(input)
        val cipher = Cipher.getInstance("RSA")
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        var temp: ByteArray  //缓存
        var offset = 0  //当前偏移
        val bos = ByteArrayOutputStream()
        while (byteArray.size - offset > 0) {
            //判断是否是最后一块
            if (byteArray.size - offset >= DECRYPT_MAX_SIZE) {
                temp = cipher.doFinal(byteArray, offset, DECRYPT_MAX_SIZE)
                offset += DECRYPT_MAX_SIZE
            } else {
                temp = cipher.doFinal(byteArray, offset, byteArray.size - offset)
                offset = byteArray.size
            }
            bos.write(temp)
        }
        bos.close()
        return String(bos.toByteArray())
    }

    fun decryptByPrivateKey2(input: String, privateKey: PrivateKey): String {
        val byteArray = Base64.getDecoder().decode(input)
        val cipher = Cipher.getInstance("RSA")
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        var offset = 0
        var tmp: ByteArray
        val bos = ByteArrayOutputStream()
        while (byteArray.size - offset > 0) {
            if (byteArray.size - offset >= 128) {
                tmp = cipher.doFinal(byteArray, offset, 128)
                offset += 128
            } else {
                tmp = cipher.doFinal(byteArray, offset, byteArray.size - offset)
                offset = byteArray.size
            }
            bos.write(tmp)
        }
        bos.close()
        return String(bos.toByteArray())
    }

    fun decryptByPublicKey(input: String, publicKey: PublicKey): String {
//        //密钥对生成器
//        val keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//        //生成密钥对
//        val keyPair  = keyPairGenerator.genKeyPair();
//        val publicKey = keyPair.public
//        val privateKey = keyPair.private


//        var key:Key ?= null
//
//        val cipher = Cipher.getInstance(transformation)
//        cipher.init(Cipher.ENCRYPT_MODE,publicKey)
//        val  encrypy = cipher.doFinal(input.toByteArray())
//
//        return Base64Util.encode(encrypy)


        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.DECRYPT_MODE, publicKey)

        //分段加密
        val byteArray = Base64Util.decode(input)


        var temp: ByteArray? = null  //缓存
        var offset = 0  //当前偏移

        val bos = ByteArrayOutputStream()

        while (byteArray.size - offset > 0) {
            //判断是否是最后一块
            if (byteArray.size - offset >= DECRYPT_MAX_SIZE) {
                temp = cipher.doFinal(byteArray, offset, DECRYPT_MAX_SIZE)
                offset += DECRYPT_MAX_SIZE
            } else {
                temp = cipher.doFinal(byteArray, offset, byteArray.size - offset)
                offset = byteArray.size
            }
            bos.write(temp)
        }

        bos.close()
        return String(bos.toByteArray())
    }


    fun getPrivateKey (): PrivateKey {



        //字符串转密钥对
        val kf = KeyFactory.getInstance("RSA")
        //只能用 Pkcs8 ,并且需要base64 解码
        val privateKey = kf.generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyStr.toByteArray())))
        // Only RSAPublicKeySpec and X509EncodedKeySpec supported for RSA public keys
        //
        val publicKey  = kf.generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyStr.toByteArray())))




        return privateKey
    }

    fun getPublicKey(): PublicKey {
        //字符串转密钥对
        val kf = KeyFactory.getInstance("RSA")
        //只能用 Pkcs8 ,并且需要base64 解码
        val privateKey = kf.generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyStr.toByteArray())))
        // Only RSAPublicKeySpec and X509EncodedKeySpec supported for RSA public keys
        //
        val publicKey  = kf.generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyStr.toByteArray())))




        return publicKey
    }


}

//rsa 非对称加密
fun main(args: Array<String>) {
    //1、创建 cipher
    //2、初始化cipher
    //3、加密/解密


    //密钥对生成器
//    val keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//    //生成密钥对
//    val keyPair = keyPairGenerator.genKeyPair();
//    val publicKey = keyPair.public
//    val privateKey = keyPair.private
//
//    println("public:" + Base64Util.encode(publicKey.encoded))
//    println("private:" + Base64Util.encode(privateKey.encoded))
//


    //保存密钥对，不要每次都生成
   val publicKeyStr  = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCRa7yJsaO4mb/xaJZvoWYWUzUiQm2858uk6eyXKOtk1qOeMks5U26nnAn4VaEYuJTUkk+pZSsPMGgwuSvFzytts0GmHybj6bEGQR/ZKJSaMDCwdoH4LBPdBOaES0ZdLyVUpgW/QWhS+hjZA5roS3TNr8fA627Frm60257OXUoWmQIDAQAB"
    val privateKeyStr  = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJFrvImxo7iZv/Folm+hZhZTNSJCbbzny6Tp7Jco62TWo54ySzlTbqecCfhVoRi4lNSST6llKw8waDC5K8XPK22zQaYfJuPpsQZBH9kolJowMLB2gfgsE90E5oRLRl0vJVSmBb9BaFL6GNkDmuhLdM2vx8DrbsWubrTbns5dShaZAgMBAAECgYASj6rP9HGORWmfeZcCBprOLK6ygcIaA4gVs5n0LU/mXhMiRQ8e8QxFroADR4K5cg3lGAu89mHJnYce+POiWvAS7ZcEH1P5P5UIDsy/k5HNyRG6jQYLkmB4DZ3h20woO2JfL2AYqbDIbKVK0HprgGaN0X9kkaA14NUZkkeXIC070QJBAOIhzv+ajCntmjzbt3xFdjhZ2yQv5L0VoX3LOgdWfYzAanMuaFxGPDNFQvo0gFnDEUx9zqrn2BR/8+MBQlmr1NUCQQCkoNgADdcLIbkU+1BVgWGEHGBkc0sWuxMoqmDoGEjs1aQ3NXmq2Z2qKNV8N8wVvmYs9fe6w9g9FOd9VrexWCy1AkEAh/008toKOJy/CKJJcd6D/ddrxhNXR67eczvoJcmJrz93xNS/xd4nDd41LSqtlU2N9aYixvyuIYXhMT7sm+iOEQJBAKLtfFgxWk3uBho5znuRHE1/N/ayE/JfGsr4NAf/YMzjcy4gglUQIfWxi/bv0c8DLGP62j3AbVWmRqPJGuss9LECQHDsYLWZL1tuQ3Gc+HvDS1yKjV9sqI0G8Ewqq88LWT0vQWbNT8yN/2yWAhvQQNX6Uem3BdkAvChAdxsGIKS1Dsg="

    //字符串转密钥对
    val kf = KeyFactory.getInstance("RSA")
    //只能用 Pkcs8 ,并且需要base64 解码
    val privateKey = kf.generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyStr.toByteArray())))
    // Only RSAPublicKeySpec and X509EncodedKeySpec supported for RSA public keys
    //
    val publicKey  = kf.generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyStr.toByteArray())))






    val input = "这是 rsa 非对称加密原文，这是长度非常长，测试分段加密，这是 rsa 非对称加密原文，这是长度非常长，测试分段加密，这是 rsa 非对称加密原文，这是长度非常长，测试分段加密，这是 rsa 非对称加密原文，这是长度非常长，测试分段加密，"
    val encrypt = RSACrypt.encryptByPublicKey(input, publicKey)
    println("加密之后:" + encrypt)

    val decrypt = RSACrypt.decryptByPrivateKey(encrypt, privateKey)
    println("私钥解密：" + decrypt)

}
