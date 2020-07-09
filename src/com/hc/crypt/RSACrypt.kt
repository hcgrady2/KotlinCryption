package com.hc.crypt

import java.io.ByteArrayOutputStream
import java.security.Key
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.util.*
import javax.crypto.Cipher

object RSACrypt {

    val transformation = "RSA"
    val encrypt_max_size = 117   //加密是 117
    val DECRYPT_MAX_SIZE = 128   //解密是 128


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

}

//rsa 非对称加密
fun main(args: Array<String>) {
    //1、创建 cipher
    //2、初始化cipher
    //3、加密/解密


    //密钥对生成器
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    //生成密钥对
    val keyPair = keyPairGenerator.genKeyPair();
    val publicKey = keyPair.public
    val privateKey = keyPair.private

    println("public:" + Base64Util.encode(publicKey.encoded))
    println("private:" + Base64Util.encode(privateKey.encoded))

    val input = "这是 rsa 非对称加密原文，这是长度非常长，测试分段加密，这是 rsa 非对称加密原文，这是长度非常长，测试分段加密，这是 rsa 非对称加密原文，这是长度非常长，测试分段加密，这是 rsa 非对称加密原文，这是长度非常长，测试分段加密，"
    val encrypt = RSACrypt.encryptByPublicKey(input, publicKey)
    println("加密之后:" + encrypt)

    val decrypt = RSACrypt.decryptByPrivateKey(encrypt, privateKey)
    println("私钥解密：" + decrypt)

}
