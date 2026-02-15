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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import java.io.File

/**
 * AI Status Screen — shows model state, capability tier, gate status,
 * download CTA, self-test results, kill switch, user LLM toggle.
 *
 * Sprint UI-2: 5/10 — real download/remove/self-test wiring.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AiStatusScreen(
    viewModel: AiStatusViewModel = hiltViewModel(),
    onBack: () -> Unit = {},
    onRunSelfTest: () -> Unit = {}
) {
    val ui by viewModel.ui.collectAsStateWithLifecycle()
    val context = LocalContext.current

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
                ui.availableStorageMb?.let { storage ->
                    StatusRow("Volné místo:", "$storage MB")
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

                ui.downloadError?.let { error ->
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = error,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }

                // Download CTA
                if (ui.canDownload) {
                    Spacer(modifier = Modifier.height(8.dp))
                    val sizeLabel = ui.modelSizeMb?.let { " ($it MB)" } ?: ""
                    Button(
                        onClick = {
                            val modelDir = File(context.filesDir, "models")
                            modelDir.mkdirs()
                            viewModel.onDownloadClick(modelDir)
                        },
                        enabled = ui.downloadProgress == null
                    ) {
                        Text("Stáhnout AI model$sizeLabel")
                    }
                }

                // Remove button
                if (ui.canRemove) {
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedButton(
                        onClick = { viewModel.onRemoveClick() },
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = MaterialTheme.colorScheme.error
                        )
                    ) {
                        Text("Smazat model")
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
                when {
                    ui.isSelfTesting -> {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            CircularProgressIndicator(modifier = Modifier.size(20.dp))
                            Text(
                                text = "Self-test probíhá…",
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }
                    ui.selfTestCompleted -> {
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
                    }
                    else -> {
                        Text(
                            text = "Self-test ještě nebyl spuštěn.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.outline
                        )
                    }
                }
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedButton(
                    onClick = {
                        viewModel.onSelfTestStarted()
                        onRunSelfTest()
                    },
                    enabled = ui.llmAvailable && !ui.killSwitchActive && !ui.isSelfTesting
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
