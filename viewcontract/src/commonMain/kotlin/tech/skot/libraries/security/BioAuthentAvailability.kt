package tech.skot.libraries.security

sealed class BioAuthentAvailability {
    object OK:BioAuthentAvailability()
    object KO:BioAuthentAvailability()
    object NONE_ENROLLED:BioAuthentAvailability()
}

//expect fun SKComponent<*>.getBioAuthentAvailability(): BioAuthentAvailability