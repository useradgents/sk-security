package tech.skot.libraries.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import tech.skot.core.SKLog
import java.nio.charset.Charset
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

object SKCrypt {

    const val keyStoreProvider = "AndroidKeyStore"

    private fun generateBioSecretKey(keyName: String, validityInSeconds: Int = 0) {
        withBiometric {

            KeyGenParameterSpec.Builder(keyName,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .setUserAuthenticationRequired(false)
                .setInvalidatedByBiometricEnrollment(true)
                .setUserAuthenticationParameters(validityInSeconds,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or
                            KeyProperties.AUTH_DEVICE_CREDENTIAL)
                .build()
                .let { keySpec ->
                    KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, keyStoreProvider)
                        .apply {
                            init(keySpec)
                            generateKey()
                        }
                }
        }
    }

    private fun getBioSecretKey(keyName: String): SecretKey {
        return KeyStore.getInstance(keyStoreProvider).apply { load(null) }
            .getKey(keyName, null) as SecretKey
    }

    private fun createCipher(): Cipher {
        return withBiometric {
            Cipher.getInstance("${KeyProperties.KEY_ALGORITHM_AES}/${KeyProperties.BLOCK_MODE_CBC}/${KeyProperties.ENCRYPTION_PADDING_PKCS7}")
        }
    }

    private const val DATA_IV_SEPARATOR = "##SKCRYPT##"


    private fun encodeBase64(input:ByteArray):String {
        return Base64.encodeToString(input, Base64.URL_SAFE)
    }

    private fun decodeBase64(input:String):ByteArray {
        return Base64.decode(input, Base64.URL_SAFE)
    }


    class SKCrypter(val cipher: Cipher, val data: ByteArray) {
        fun encode():String {
            SKLog.d("--- will encode ${data.toString(Charset.defaultCharset())}")
            val encodedData = cipher.doFinal(data)
            val base64EncodedData = encodeBase64(encodedData)
            val base64Iv = encodeBase64(cipher.iv)
            SKLog.d("--- has encoded : base64EncodedData $base64EncodedData")
            return "$base64EncodedData$DATA_IV_SEPARATOR$base64Iv"
        }
    }

    fun getCrypter(keyName: String, data: String): SKCrypter {
        return withBiometric {
            SKCrypter(createCipher().apply {
                generateBioSecretKey(keyName)
                init(Cipher.ENCRYPT_MODE, getBioSecretKey(keyName))
            }, data.toByteArray(Charset.defaultCharset()))
        }
    }


    class SKDeCrypter(val cipher: Cipher, val data: ByteArray) {
        fun decode():String {
            SKLog.d("--- will decode : base64EncodedData ${data.toString(Charset.defaultCharset())}")
            val decodedData = cipher.doFinal(data)
            return decodedData.toString(Charset.defaultCharset())
        }
    }

    fun getDeCrypter(keyName: String, skEncodedData: String): SKDeCrypter {
        val tab = skEncodedData.split(DATA_IV_SEPARATOR)
        val base64EncodedData = tab[0]
        val base64Iv = tab[1]
        return withBiometric {
            SKDeCrypter(createCipher().apply {
                init(Cipher.DECRYPT_MODE, getBioSecretKey(keyName), IvParameterSpec(
                    decodeBase64(base64Iv)
                ))

            }, decodeBase64(base64EncodedData))
        }
    }



//    fun decode(encodedDataAndIv:String, initializedCipher: Cipher):String {
//        return encodedDataAndIv.split(DATA_IV_SEPARATOR).let {
//            val encodedData = it[0]
//            val base64Iv = it[1]
//
//            initializedCipher.
//        }
//    }
}