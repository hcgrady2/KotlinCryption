package com.hc.crypt

import java.security.Key
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.DESKeySpec

//将 des 封装成工具类，object 指定单例模式
object AESCrypt{

    //des 加密
    fun encrypt(input:String,password:String): String {
        //参考 java 文档 Cipher
        //1 、创建 cipher 对象
        var cipher = Cipher.getInstance("AES")

        //解密解密的 key
        val keySpec = DESKeySpec(password.toByteArray())  //里面指定自己的密码
        val kf  = SecretKeyFactory.getInstance("AES")  //DES 的密钥工厂

        var key: Key? = kf.generateSecret(keySpec)     //通过密码创建 key


        //2 初始化，指定加密或者解密模式，key
        cipher.init(Cipher.ENCRYPT_MODE,key)


        //3 加密和解密
        val encrypt = cipher.doFinal(input.toByteArray())

        //  return String(encrypt)
        return Base64Util.encode(encrypt)
    }



    //des 解密
    fun decrypt(input:String,password:String): ByteArray{
        //    var input = "这是 des 加密解密的原文"
        //  val password = "thisIsMyPwd"

        //参考 java 文档 Cipher
        //1 、创建 cipher 对象
        var cipher = Cipher.getInstance("AES")

        //解密解密的 key
        val keySpec = DESKeySpec(password.toByteArray())  //里面指定自己的密码
        val kf  = SecretKeyFactory.getInstance("AES")  //AES 的密钥工厂

        var key: Key? = kf.generateSecret(keySpec)     //通过密码创建 key


        //2 初始化，指定加密或者解密模式，key
        cipher.init(Cipher.DECRYPT_MODE,key)


        //3 加密和解密
        //Base64 解码
        val encrypt = cipher.doFinal(Base64Util.decode(input))

        return encrypt
    }

}

fun main (args: Array<String>){

    var input = "这是 Aes 加密解密的原文"
    val password = "thisIsMyPwd"
//
//    //参考 java 文档 Cipher
//    //1 、创建 cipher 对象
//    var cipher = Cipher.getInstance("DES")
//
//    //解密解密的 key
//    val keySpec = DESKeySpec(password.toByteArray())  //里面指定自己的密码
//    val kf  = SecretKeyFactory.getInstance("DES")  //DES 的密钥工厂
//
//    var key:Key? = kf.generateSecret(keySpec)     //通过密码创建 key
//
//
//    //2 初始化，指定加密或者解密模式，key
//    cipher.init(Cipher.ENCRYPT_MODE,key)
//
//
//    //3 加密和解密
//    val encrypt = cipher.doFinal(input.toByteArray())



    // 中文是 utf-8 编码，每个中文是 3 个字节（不同计算机不一样）
    //加密后长度边长，导致映射符号表找不到正确的字符，并且总长度不是字符的长度的整数倍，导致解码失败
    //一般都转成  base64 在进行加密解密
    var array = input.toByteArray()
    val encrypt  = DESCrypt.encrypt(input ,password )
    println("Aes 加密:" + encrypt )

    var decrypt = DESCrypt.decrypt(encrypt,password)
    println("解密 :" + String(decrypt))
}