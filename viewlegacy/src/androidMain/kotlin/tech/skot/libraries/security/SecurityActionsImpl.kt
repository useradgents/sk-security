package tech.skot.libraries.security

import android.content.Intent
import android.os.Build
import android.provider.Settings
import android.view.View
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import tech.skot.core.SKLog
import tech.skot.core.components.SKActivity
import java.security.UnrecoverableKeyException

class SecurityActionsImpl(
    private val activity: SKActivity,
    private val fragment: Fragment?,
    private val root: View,
) : SecurityActions {
    override fun getBioAuthentAvailability(
        onResult: (availability: BioAuthentAvailability) -> Unit,
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {

            when (BiometricManager.from(activity)
                .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)) {
                BiometricManager.BIOMETRIC_SUCCESS -> {
                    onResult(BioAuthentAvailability.OK)
                }
                BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE, BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
                    onResult(BioAuthentAvailability.KO)
                }
                BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                    onResult(BioAuthentAvailability.NONE_ENROLLED)
                }
            }
        } else {
            onResult(BioAuthentAvailability.KO)
        }
    }


    override fun doWithBioAuthent(
        title: CharSequence,
        subTitle: CharSequence?,
        onKo: (() -> Unit)?,
        onOk: () -> Unit,
    ) {
        BiometricPrompt(activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    onOk()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    onKo?.invoke()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    onKo?.invoke()
                }
            }
        ).authenticate(
            getPromptInfos(title, subTitle)
        )
    }

    override fun enrollBioAuthent() {
        withBiometric {
            activity.startActivity(Intent(Settings.ACTION_BIOMETRIC_ENROLL).apply {
                putExtra(Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED,
                    BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
            })
        }
    }

    private fun getPromptInfos(
        title: CharSequence,
        subTitle: CharSequence?,
    ): BiometricPrompt.PromptInfo {
        return BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subTitle)
            .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
            .build()
    }

    override fun encodeWithBioAuthent(
        title: CharSequence,
        subTitle: CharSequence?,
        keyName: String,
        strData: String,
        onOk: ((encryptedData: String) -> Unit),
        onKo: ((error: Boolean) -> Unit)?,
    ) {
        withBiometric {
            val skCrypter = SKCrypt.getCrypter(keyName, strData)
            BiometricPrompt(activity,
                ContextCompat.getMainExecutor(activity),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(result)
                        try {
                            skCrypter.encode()
                        }
                        catch (ex:Exception) {
                            onKo?.invoke(true)
                            null
                        }?.let(onOk)
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        super.onAuthenticationError(errorCode, errString)
                        onKo?.invoke(true)
                    }

                    override fun onAuthenticationFailed() {
                        super.onAuthenticationFailed()
                        onKo?.invoke(false)
                    }
                }
            ).authenticate(
                getPromptInfos(title, subTitle),
                BiometricPrompt.CryptoObject(skCrypter.cipher)
            )
        }
    }

    override fun decodeWithBioAuthent(
        title: CharSequence,
        subTitle: CharSequence?,
        keyName: String,
        skEncodedData: String,
        onOk: ((decryptedData: String) -> Unit),
        onUnrecoverableKey:()->Unit,
        onKo: ((error: Boolean) -> Unit)?,
    ) {
        try {
            val skCrypter = SKCrypt.getDeCrypter(keyName, skEncodedData)
            BiometricPrompt(activity,
                ContextCompat.getMainExecutor(activity),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(result)
                        try {
                            onOk(skCrypter.decode())
                        } catch (ex: Exception) {
                            SKLog.e(ex, "Error on decoding")
                            onKo?.invoke(true)
                        }

                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        super.onAuthenticationError(errorCode, errString)
                        SKLog.e(Exception("Error on authentication"),
                            "onAuthenticationError :$errString")
                        onKo?.invoke(true)
                    }

                    override fun onAuthenticationFailed() {
                        super.onAuthenticationFailed()
                        onKo?.invoke(false)
                    }
                }
            ).authenticate(
                getPromptInfos(title, subTitle),
                BiometricPrompt.CryptoObject(skCrypter.cipher)
            )
        }
        catch (ex: UnrecoverableKeyException) {
            SKLog.e(ex,"La clé ne peut être récupérée, les credentials ont dû changer")
            onUnrecoverableKey.invoke()
        }

    }
}