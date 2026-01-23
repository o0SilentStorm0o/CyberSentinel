package com.cybersentinel.ui.screens.password

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

data class PasswordUiState(
    val password: String = "",
    val isVisible: Boolean = false,
    val isChecking: Boolean = false,
    val liveStrength: StrengthScore? = null,  // lokální odhad při psaní
    val result: HibpResult? = null,
    val errorSnack: String? = null,
    val retryCount: Int = 0
)

/** Úroveň pro zobrazení (kompromitované heslo nikdy nebude „zelené"). */
private fun displayLevel(compromised: Boolean, count: Long, strength: StrengthScore?): StrengthLevel {
    return when {
        compromised && count > 100_000 -> StrengthLevel.VERY_WEAK
        compromised -> StrengthLevel.WEAK
        else -> strength?.level ?: StrengthLevel.MEDIUM
    }
}

@HiltViewModel
class PasswordCheckViewModel @Inject constructor(
    private val checker: HibpPasswordChecker
) : ViewModel() {

    private val _ui = MutableStateFlow(PasswordUiState())
    val ui: StateFlow<PasswordUiState> = _ui

    fun onPasswordChange(newValue: String) {
        _ui.update { it.copy(password = newValue, result = null, retryCount = 0) }
        // Live strength (bez sítě)
        if (newValue.isNotBlank()) {
            val chars = newValue.toCharArray()
            val s = try { checker.quickEstimate(chars) } finally { chars.fill('\u0000') }
            _ui.update { it.copy(liveStrength = s) }
        } else {
            _ui.update { it.copy(liveStrength = null) }
        }
    }

    fun onToggleVisibility() = _ui.update { it.copy(isVisible = !it.isVisible) }

    fun clearPassword() = _ui.update { it.copy(password = "", liveStrength = null, result = null, retryCount = 0) }

    fun onCheck() {
        val pw = _ui.value.password
        if (pw.isBlank() || _ui.value.isChecking) return
        _ui.update { it.copy(isChecking = true, result = null, retryCount = it.retryCount + 1) }

        viewModelScope.launch {
            val chars = pw.toCharArray()
            val res = try { checker.checkPassword(chars) } finally { chars.fill('\u0000') }
            _ui.update { it.copy(isChecking = false, result = res) }
        }
    }

    fun onRetry() = onCheck()

    /** Pomocník pro UI – vrací úroveň a barvu podle výsledku nebo live síly. */
    fun deriveDisplayLevel(): StrengthLevel {
        val r = _ui.value.result
        return when (r) {
            is HibpResult.Ok -> displayLevel(r.compromised, r.breachCount, r.strength)
            else -> displayLevel(compromised = false, count = 0, strength = _ui.value.liveStrength)
        }
    }
}