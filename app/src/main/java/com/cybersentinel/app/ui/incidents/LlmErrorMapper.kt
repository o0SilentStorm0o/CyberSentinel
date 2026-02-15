package com.cybersentinel.app.ui.incidents

/**
 * LlmErrorMapper — maps ERR|CODE strings from LlamaCppRuntime
 * to Czech user-friendly error messages.
 *
 * The LLM runtime produces error codes like:
 *  ERR|NULL_HANDLE, ERR|STALE_HANDLE, ERR|POISONED, ERR|NULL_CTX,
 *  ERR|NULL_PROMPT, ERR|TOKENIZE, ERR|CTX_OVERFLOW, ERR|DECODE
 *
 * These are meaningless to end users. This mapper converts them
 * to helpful, non-technical Czech messages with actionable suggestions.
 *
 * Sprint UI-2: 8/10 — ERR|CODE user-friendly messaging.
 */
object LlmErrorMapper {

    private val errorMap = mapOf(
        "ERR|NULL_HANDLE" to "AI model není načten. Zkuste ho znovu stáhnout v nastavení AI.",
        "ERR|STALE_HANDLE" to "Relace AI modelu vypršela. Zkuste to znovu.",
        "ERR|POISONED" to "AI model je v chybovém stavu. Smažte ho a stáhněte znovu.",
        "ERR|NULL_CTX" to "AI kontext nebyl inicializován. Zkuste to znovu.",
        "ERR|NULL_PROMPT" to "Interní chyba — prázdný dotaz. Zkuste to znovu.",
        "ERR|TOKENIZE" to "AI nedokázal zpracovat text. Zkuste kratší popis incidentu.",
        "ERR|CTX_OVERFLOW" to "Incident je příliš rozsáhlý pro AI. Používám šablonové vysvětlení.",
        "ERR|DECODE" to "AI vysvětlení selhalo při generování. Zkuste to znovu."
    )

    /**
     * Convert an error message (possibly containing ERR|CODE) to a user-friendly Czech string.
     *
     * If the message contains a known ERR|CODE, returns the mapped message.
     * Otherwise, wraps the original message in a generic error sentence.
     */
    fun toUserMessage(rawMessage: String): String {
        // Check for known ERR|CODE patterns
        for ((code, userMsg) in errorMap) {
            if (rawMessage.contains(code)) {
                return userMsg
            }
        }

        // Generic fallback
        return if (rawMessage.isBlank()) {
            "Vysvětlení selhalo. Zkuste to znovu."
        } else {
            "Vysvětlení selhalo: $rawMessage"
        }
    }

    /**
     * Check if the error message contains a known ERR|CODE.
     */
    fun isKnownError(rawMessage: String): Boolean {
        return errorMap.keys.any { rawMessage.contains(it) }
    }

    /**
     * Get all known error codes (for testing).
     */
    internal fun knownCodes(): Set<String> = errorMap.keys
}
