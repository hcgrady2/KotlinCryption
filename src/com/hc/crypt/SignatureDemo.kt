package com.hc.crypt

import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature


object  SignatureUtil{

    fun  sign(input:String,privateKey:PrivateKey): String {

     //   val input = "这是数据源"

      //  val privateKey = RSACrypt.getPrivateKey()

        //获取实例
        val signature = Signature.getInstance("SHA256withRSA")
        //初始化
        signature.initSign(privateKey)
        //设置数据源
        signature.update(input.toByteArray())

        //签名
        val sign = signature.sign()


        return Base64Util.encode(sign)

    }


    fun verify(input:String,publicKey: PublicKey,sign:String): Boolean {
      //  val publicKey = RSACrypt.getPublicKey()
        val signature = Signature.getInstance("SHA256withRSA")
        signature.initVerify(publicKey)
        signature.update(input.toByteArray())
        val verify = signature.verify(Base64Util.decode(sign))
        println("校验:" + verify)
        return verify
    }

}

fun main(args: Array<String>) {

    val input = "这是数据源"

    val privateKey = RSACrypt.getPrivateKey()

//    //获取实例
//    val signature = Signature.getInstance("SHA256withRSA")
//    //初始化
//    signature.initSign(privateKey)
//    //设置数据源
//    signature.update(input.toByteArray())
//
//    //签名
//    val sign = signature.sign()


    val sign = SignatureUtil.sign(input,privateKey)

    println(sign)



    val publicKey = RSACrypt.getPublicKey()
//    val signature = Signature.getInstance("SHA256withRSA")
//    signature.initVerify(publicKey)
//    signature.update(input.toByteArray())
//    val verify = signature.verify(Base64Util.decode(sign))
//    println("校验:" + verify)
//



    val verify = SignatureUtil.verify(input,publicKey,sign)
    println("校验:" + verify)


}