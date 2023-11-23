package com.example.integritycheck

import java.security.MessageDigest
import java.util.*

object Utils {

    fun sha1(input: ByteArray) = hashString("SHA-1", input)
    fun sha256(input: ByteArray) = hashString("SHA-256", input)

    private fun bytesToHex(input: ByteArray): String {
        val builder = StringBuilder()
        for (b in input) {
            builder.append(String.format("%02x", b))
        }
        return builder.toString()
    }

    private fun hashString(type: String, input: ByteArray): String {
        val bytes = MessageDigest
            .getInstance(type)
            .digest(input)
        return bytesToHex(bytes).uppercase(Locale.getDefault())
    }

}