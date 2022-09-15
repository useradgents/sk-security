package tech.skot.libraries.security

interface SecurityActions {
    fun getBioAuthentAvailability(
        onResult: (availability: BioAuthentAvailability) -> Unit,
    )

    fun doWithBioAuthent(
        title: CharSequence,
        subTitle: CharSequence? = null,
        onKo: (() -> Unit)? = null,
        onOk: () -> Unit,
    )

    fun enrollBioAuthent()

    fun encodeWithBioAuthent(
        title: CharSequence,
        subTitle: CharSequence?,
        keyName: String,
        strData: String,
        onOk:((encryptedData:String)->Unit),
        onKo:((error:Boolean)->Unit)? = null,
    )

    fun decodeWithBioAuthent(
        title: CharSequence,
        subTitle: CharSequence?,
        keyName: String,
        skEncodedData: String,
        onOk:((decryptedData:String)->Unit),
        onKo:((error:Boolean)->Unit)? = null,
    )
}