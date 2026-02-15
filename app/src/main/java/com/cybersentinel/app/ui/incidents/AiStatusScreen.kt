package com.cybersentinel.app.ui.incidents

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
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
 * Sprint UI-3: Complete control panel with cancel, metrics, self-test pipeline.
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
            // ── Model state (download / cancel / re-download) ──
            StatusCard(title = "Stav modelu") {
                StatusRow("Model:", ui.modelStateLabel)
                StatusRow("Tier:", ui.tierLabel)

                if (ui.modelSizeMb != null) {
                    StatusRow("Velikost:", "${ui.modelSizeMb} MB")
                }
                ui.availableStorageMb?.let { storage ->
                    StatusRow("Volné místo:", "$storage MB")
                }

                // Download progress + cancel
                ui.downloadProgress?.let { progress ->
                    Spacer(modifier = Modifier.height(8.dp))
                    LinearProgressIndicator(
                        progress = { progress },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "${(progress * 100).toInt()} %",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.outline
                        )
                        TextButton(onClick = { viewModel.onCancelDownload() }) {
                            Text("Zrušit", color = MaterialTheme.colorScheme.error)
                        }
                    }
                }

                // Download error + re-download button
                ui.downloadError?.let { error ->
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = error,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Button(onClick = {
                        val modelDir = File(context.filesDir, "models")
                        modelDir.mkdirs()
                        viewModel.onRedownloadClick(modelDir)
                    }) {
                        Text("Smazat a stáhnout znovu")
                    }
                }

                // Download CTA
                if (ui.canDownload && ui.downloadError == null) {
                    Spacer(modifier = Modifier.height(8.dp))
                    val sizeLabel = ui.modelSizeMb?.let { " ($it MB)" } ?: ""
                    Button(
                        onClick = {
                            val modelDir = File(context.filesDir, "models")
                            modelDir.mkdirs()
                            viewModel.onDownloadClick(modelDir)
                        },
                        enabled = !ui.isDownloading
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
                        // Production ready badge
                        val badge = if (ui.isProductionReady == true)
                            "✅ Production ready" else "❌ Nedostatečný"
                        Surface(
                            shape = RoundedCornerShape(8.dp),
                            color = if (ui.isProductionReady == true)
                                MaterialTheme.colorScheme.primaryContainer
                            else
                                MaterialTheme.colorScheme.errorContainer
                        ) {
                            Text(
                                text = badge,
                                modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.Bold
                            )
                        }
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

            // ── Metrics (shown only after self-test) ──
            ui.benchmarkMetrics?.let { metrics ->
                MetricsCard(metrics)
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

@Composable
private fun MetricsCard(metrics: BenchmarkMetricsUi) {
    var expanded by remember { mutableStateOf(false) }

    StatusCard(title = "Metriky výkonu") {
        // Primary metrics
        StatusRow("Průměrná latence:", "${metrics.avgLatencyMs} ms")
        StatusRow("P95 latence:", "${metrics.p95LatencyMs} ms")
        StatusRow("Spolehlivost:", "${metrics.reliabilityPercent} %")
        StatusRow("Porušení politik:", "${metrics.policyViolationPercent} %")
        StatusRow("Špička paměti:", "${metrics.peakHeapMb} MB")
        StatusRow("Health score:", "${metrics.healthScore}")

        // Expandable advanced section
        Spacer(modifier = Modifier.height(8.dp))
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { expanded = !expanded }
                .padding(vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "Pokročilé",
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.weight(1f)
            )
            Icon(
                imageVector = if (expanded) Icons.Default.KeyboardArrowUp
                else Icons.Default.KeyboardArrowDown,
                contentDescription = if (expanded) "Skrýt" else "Zobrazit"
            )
        }

        AnimatedVisibility(visible = expanded) {
            Column {
                StatusRow("P99 latence:", "${metrics.p99LatencyMs} ms")
                StatusRow("Tokeny/s:", "${metrics.avgTokensPerSecond}")
                StatusRow("Template fallback:", "${metrics.templateFallbackPercent} %")
                StatusRow("Stop failure:", "${metrics.stopFailurePercent} %")
                StatusRow("Průměr tokenů:", "${metrics.avgGeneratedTokens}")
                StatusRow("Max tokenů:", "${metrics.maxGeneratedTokens}")
                StatusRow("OOM:", "${metrics.oomCount}")
                StatusRow("Timeout:", "${metrics.timeoutCount}")
                StatusRow("Celkem runs:", "${metrics.totalRuns}")
            }
        }
    }
}
