package com.hc.crypt

import java.lang.StringBuilder
import java.security.MessageDigest

object MessageDigetUitl{


    fun md5(input:String ): String {
        val digest = MessageDigest.getInstance("MD5")

        val result = digest.digest(input.toByteArray())

        val stringBuilder = StringBuilder()
        //转成 16 进制
        result.forEach {
            val value = it
            //移位操作
            val hex = value.toInt() and (0xFF)
            val hexStr = Integer.toHexString(hex)

            //如果是一位，则前面加0
            if (hexStr.length == 1) {
                stringBuilder.append("0").append(hexStr)
            } else {
                stringBuilder.append(hexStr)
            }

            //println(stringBuilder.toString())

        }
        return stringBuilder.toString()


    }
}

fun main(args:Array<String>){

//    val input = "这是加密之前原文"
//
//    val digest = MessageDigest.getInstance("MD5")
//
//    val result = digest.digest(input.toByteArray())
//
//    val stringBuilder = StringBuilder()
//    //转成 16 进制
//    result.forEach {
//        println(it)
//        val value = it
//        //移位操作
//        val hex = value.toInt() and (0xFF)
//        val hexStr = Integer.toHexString(hex)
//
//        //如果是一位，则前面加0
//        if (hexStr.length == 1){
//            stringBuilder.append("0").append(hexStr)
//        }else{
//            stringBuilder.append(hexStr)
//        }
//
//        println(stringBuilder.toString())
//
//    }

    val input = "这是加密之前原文"
    val md5 = MessageDigetUitl.md5(input)
    println(md5)
}
