package com.cybersentinel.app.ui.incidents

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/**
 * AI Status Screen — shows model state, capability tier, gate status,
 * download CTA, self-test results, kill switch, user LLM toggle.
 *
 * Feature gating:
 *  - TIER_0: AI completely hidden or disabled with explanation
 *  - Model NOT_DOWNLOADED: shows download CTA with size
 *  - Power saver / thermal: shows "Teď ne" with template fallback note
 *
 * Sprint UI-1: Model manager UI.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AiStatusScreen(
    viewModel: AiStatusViewModel = hiltViewModel(),
    onBack: () -> Unit = {},
    onRunSelfTest: () -> Unit = {}
) {
    val ui by viewModel.ui.collectAsStateWithLifecycle()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("AI & Model") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Zpět")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // ── Model state ──
            StatusCard(title = "Stav modelu") {
                StatusRow("Model:", ui.modelStateLabel)
                StatusRow("Tier:", ui.tierLabel)

                if (ui.modelSizeMb != null) {
                    StatusRow("Velikost:", "${ui.modelSizeMb} MB")
                }

                ui.downloadProgress?.let { progress ->
                    Spacer(modifier = Modifier.height(8.dp))
                    LinearProgressIndicator(
                        progress = { progress },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Text(
                        text = "${(progress * 100).toInt()} %",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.outline
                    )
                }

                // Download CTA when model is missing
                if (ui.modelStateLabel == "Nestažen") {
                    Spacer(modifier = Modifier.height(8.dp))
                    val sizeLabel = ui.modelSizeMb?.let { " ($it MB)" } ?: ""
                    Button(onClick = { /* TODO: wire modelManager.downloadModel() */ }) {
                        Text("Stáhnout AI model$sizeLabel")
                    }
                }
            }

            // ── Gate status ──
            StatusCard(title = "Přístup k AI") {
                StatusRow(
                    "Stav:",
                    if (ui.llmAvailable) "✅ Povoleno" else "❌ Blokováno"
                )
                StatusRow("Důvod:", ui.gateReason)
            }

            // ── Kill switch ──
            if (ui.killSwitchActive) {
                Card(
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer
                    )
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = "⚠️ Kill switch aktivní",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.error
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "AI model byl zakázán administrátorem. Používá se šablonový engine.",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }

            // ── User toggle ──
            StatusCard(title = "Preference uživatele") {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "Povolit AI vysvětlení",
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Switch(
                        checked = ui.userLlmEnabled,
                        onCheckedChange = { viewModel.toggleUserLlm(it) }
                    )
                }
                Text(
                    text = "Když je vypnuté, používá se šablonový engine bez LLM.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.outline
                )
            }

            // ── Self-test ──
            StatusCard(title = "Self-test") {
                if (ui.selfTestCompleted) {
                    StatusRow(
                        "Výsledek:",
                        if (ui.isProductionReady == true) "✅ Production ready" else "❌ Nedostatečný"
                    )
                    ui.selfTestSummary?.let { summary ->
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = summary,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                } else {
                    Text(
                        text = "Self-test ještě nebyl spuštěn.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.outline
                    )
                }
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedButton(
                    onClick = onRunSelfTest,
                    enabled = ui.llmAvailable && !ui.killSwitchActive
                ) {
                    Text("Spustit self-test")
                }
            }
        }
    }
}

// ──────────────────────────────────────────────────────────
//  Helpers
// ──────────────────────────────────────────────────────────

@Composable
private fun StatusCard(
    title: String,
    content: @Composable ColumnScope.() -> Unit
) {
    Card(
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold
            )
            Spacer(modifier = Modifier.height(8.dp))
            content()
        }
    }
}

@Composable
private fun StatusRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.outline
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Medium
        )
    }
}
