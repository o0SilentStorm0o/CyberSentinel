package com.cybersentinel.app.ui.screens

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.cybersentinel.app.data.repo.CveRepository
import com.cybersentinel.app.domain.device.DeviceProfileProvider
import com.cybersentinel.app.domain.scoring.RelevantCve
import com.cybersentinel.app.domain.scoring.relevance
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.launch
import javax.inject.Inject

private const val PAGE_SIZE = 50

data class CveUiState(
    val loading: Boolean = false,
    val error: String? = null,
    val relevantOnly: Boolean = true,
    val daysBack: Int = 365,
    val items: List<RelevantCve> = emptyList(),
    val canLoadMore: Boolean = true
)

@HiltViewModel
class CveViewModel @Inject constructor(
    private val repo: CveRepository,
    profileProvider: DeviceProfileProvider
) : ViewModel() {

    private val profile = profileProvider.get()
    private var currentPage = 0
    private var backingAll: MutableList<RelevantCve> = mutableListOf()

    private val _ui = MutableStateFlow(CveUiState(loading = true))
    val ui: StateFlow<CveUiState> = _ui.asStateFlow()

    // Backward compatibility
    val state: StateFlow<CveState> = _ui.asStateFlow().map { uiState ->
        when {
            uiState.loading -> CveState.Loading
            uiState.error != null -> CveState.Error(uiState.error)
            else -> CveState.Ready(uiState.items)
        }
    }.stateIn(viewModelScope, SharingStarted.Lazily, CveState.Loading)

    val relevantOnly = MutableStateFlow(true)

    init { refresh() }

    fun toggleRelevant(only: Boolean) {
        relevantOnly.value = only
        _ui.update { it.copy(relevantOnly = only) }
        // pro „Relevant off" můžeš zobrazit CIRCL, ale držme NVD kvůli stránkování
        refresh(resetPage = true)
    }

    fun setDaysBack(days: Int) {
        _ui.update { it.copy(daysBack = days) }
        refresh(resetPage = true)
    }

    fun loadMore() {
        if (!ui.value.canLoadMore || ui.value.loading) return
        fetch(page = currentPage + 1, append = true)
    }

    fun refresh(resetPage: Boolean = true) {
        if (resetPage) currentPage = 0
        backingAll.clear()
        fetch(page = 0, append = false)
    }

    fun acknowledge(cveId: String) {
        viewModelScope.launch {
            repo.acknowledge(cveId)
            // Remove from current list
            backingAll.removeAll { it.item.id == cveId }
            val filteredItems = if (ui.value.relevantOnly) {
                backingAll.filter { it.score >= 4 }
            } else {
                backingAll
            }
            _ui.update { it.copy(items = filteredItems.toList()) }
        }
    }

    private fun fetch(page: Int, append: Boolean) {
        viewModelScope.launch {
            _ui.update { it.copy(loading = true, error = null) }
            try {
                val nvd = repo.searchNvdForDevice(
                    daysBack = ui.value.daysBack,
                    page = page,
                    pageSize = PAGE_SIZE,
                    profile = profile
                )
                val ranked = nvd.map { relevance(it, profile) }
                    .sortedByDescending { it.score }

                if (append) {
                    backingAll.addAll(ranked)
                } else {
                    backingAll = ranked.toMutableList()
                }

                currentPage = page
                val filteredItems = if (ui.value.relevantOnly) {
                    backingAll.filter { it.score >= 4 }
                } else {
                    backingAll
                }
                
                _ui.update {
                    it.copy(
                        loading = false,
                        items = filteredItems.toList(),
                        canLoadMore = ranked.isNotEmpty()
                    )
                }
            } catch (t: Throwable) {
                // Graceful fallback na CIRCL API
                when {
                    t.message?.contains("404") == true || 
                    t.message?.contains("400") == true ||
                    t.message?.contains("HTTP") == true -> {
                        fallbackToCircl()
                    }
                    else -> {
                        _ui.update { it.copy(loading = false, error = t.message ?: "Network error") }
                    }
                }
            }
        }
    }

    private suspend fun fallbackToCircl() {
        try {
            val circl = repo.loadLatest()
            val ranked = circl.map { relevance(it, profile) }
                .sortedByDescending { it.score }
            
            backingAll = ranked.toMutableList()
            
            val filteredItems = if (ui.value.relevantOnly) {
                backingAll.filter { it.score >= 4 }
            } else {
                backingAll
            }
            
            _ui.update {
                it.copy(
                    loading = false,
                    items = filteredItems.toList(),
                    canLoadMore = false, // CIRCL nemá stránkování
                    error = "NVD nedostupné, zobrazuji otevřený CIRCL feed"
                )
            }
        } catch (e: Throwable) {
            _ui.update { 
                it.copy(
                    loading = false, 
                    error = "NVD i CIRCL nedostupné: ${e.message}"
                ) 
            }
        }
    }
}

// Backward compatibility sealed interface
sealed interface CveState {
    data object Loading : CveState
    data class Ready(val items: List<RelevantCve>) : CveState
    data class Error(val message: String) : CveState
}