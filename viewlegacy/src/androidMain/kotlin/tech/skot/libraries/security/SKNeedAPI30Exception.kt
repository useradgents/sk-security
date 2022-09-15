package tech.skot.libraries.security

import android.os.Build

object SKNeedAPI30Exception: Exception("API 30 required for using string Biometric Authentication")


inline fun <R>withBiometric(block:()->R):R {
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        block()
    }
    else {
        throw SKNeedAPI30Exception
    }
}