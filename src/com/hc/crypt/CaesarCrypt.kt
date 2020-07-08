package com.hc.crypt


fun main(args: Array<String>){

    val c = 'A';

    var ascii = c.toInt()

    //移动一位
    ascii+=1

    var result = ascii.toChar()

    println(result)


}