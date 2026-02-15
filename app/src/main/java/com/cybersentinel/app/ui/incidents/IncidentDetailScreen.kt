package com.cybersentinel.app.ui.incidents

import android.content.Context
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/**
 * Incident Detail Screen — 5-section layout from the spec:
 *  1. "Co se děje" (summary)
 *  2. "Proč si to myslíme" (max 3 evidence reasons)
 *  3. "Co udělat teď" (max 3 action steps with CTA)
 *  4. "Kdy to ignorovat"
 *  5. "Technické detaily" (collapsed)
 *
 * + "Vysvětlit" button for on-demand LLM explanation with loading/cancel.
 * + Engine attribution badge + isBusyFallback indicator.
 *
 * Sprint UI-1: Incident detail MVP.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun IncidentDetailScreen(
    viewModel: IncidentDetailViewModel = hiltViewModel(),
    onBack: () -> Unit = {}
) {
    val ui by viewModel.ui.collectAsStateWithLifecycle()
    val context = LocalContext.current

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = ui.detail?.title ?: "Detail incidentu",
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Zpět")
                    }
                }
            )
        }
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            when {
                ui.isLoading -> {
                    CircularProgressIndicator(modifier = Modifier.align(Alignment.Center))
                }

                ui.error != null -> {
                    Text(
                        text = ui.error!!,
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier
                            .align(Alignment.Center)
                            .padding(16.dp)
                    )
                }

                ui.detail != null -> {
                    DetailContent(
                        detail = ui.detail!!,
                        explanationState = ui.explanationState,
                        onExplain = { viewModel.requestExplanation() },
                        onCancelExplain = { viewModel.cancelExplanation() },
                        context = context
                    )
                }
            }
        }
    }
}

@Composable
private fun DetailContent(
    detail: IncidentDetailModel,
    explanationState: ExplanationUiState,
    onExplain: () -> Unit,
    onCancelExplain: () -> Unit,
    context: Context
) {
    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Header: severity + status + engine badge
        item {
            DetailHeader(detail)
        }

        // Section 1: "Co se děje"
        item {
            SectionCard(title = "Co se děje") {
                Text(
                    text = detail.whatHappened,
                    style = MaterialTheme.typography.bodyMedium
                )
            }
        }

        // Section 2: "Proč si to myslíme"
        if (detail.reasons.isNotEmpty()) {
            item {
                SectionCard(title = "Proč si to myslíme") {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        detail.reasons.forEach { reason ->
                            ReasonRow(reason)
                        }
                    }
                }
            }
        }

        // Section 3: "Co udělat teď"
        if (detail.actions.isNotEmpty()) {
            item {
                SectionCard(title = "Co udělat teď") {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        detail.actions.forEach { action ->
                            ActionRow(action, context)
                        }
                    }
                }
            }
        }

        // Section 4: "Kdy to ignorovat"
        if (!detail.whenToIgnore.isNullOrBlank()) {
            item {
                SectionCard(title = "Kdy to ignorovat") {
                    Text(
                        text = detail.whenToIgnore,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        // Section 5: "Technické detaily" (collapsed)
        item {
            TechnicalDetailsSection(detail.technicalDetails)
        }

        // "Vysvětlit" button + explanation state
        item {
            ExplanationSection(
                state = explanationState,
                isBusyFallback = detail.isBusyFallback,
                engineSourceLabel = detail.engineSourceLabel,
                onExplain = onExplain,
                onCancel = onCancelExplain
            )
        }
    }
}

// ──────────────────────────────────────────────────────────
//  Header
// ──────────────────────────────────────────────────────────

@Composable
private fun DetailHeader(detail: IncidentDetailModel) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        SeverityBadge(detail.severity)

        // Engine attribution
        detail.engineSourceLabel?.let { label ->
            Surface(
                shape = RoundedCornerShape(6.dp),
                color = MaterialTheme.colorScheme.tertiaryContainer
            ) {
                Text(
                    text = label,
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onTertiaryContainer
                )
            }
        }
    }

    if (detail.isBusyFallback) {
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = "⚡ AI bylo zaneprázdněné — zobrazujeme šablonové vysvětlení.",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.outline
        )
    }
}

// ──────────────────────────────────────────────────────────
//  Section card wrapper
// ──────────────────────────────────────────────────────────

@Composable
private fun SectionCard(
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

// ──────────────────────────────────────────────────────────
//  Reason row (Section 2)
// ──────────────────────────────────────────────────────────

@Composable
private fun ReasonRow(reason: ReasonUiModel) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.Top
    ) {
        // Hard evidence indicator
        if (reason.isHardEvidence) {
            Icon(
                imageVector = Icons.Default.Warning,
                contentDescription = "Silný důkaz",
                modifier = Modifier
                    .size(16.dp)
                    .padding(end = 4.dp),
                tint = Color(0xFFF57C00)
            )
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = reason.text,
                style = MaterialTheme.typography.bodySmall
            )
            Text(
                text = reason.findingTag,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.outline
            )
        }
    }
}

// ──────────────────────────────────────────────────────────
//  Action row with CTA (Section 3)
// ──────────────────────────────────────────────────────────

@Composable
private fun ActionRow(action: ActionUiModel, context: Context) {
    val intent = remember(action.actionCategory, action.targetPackage) {
        ActionIntentMapper.createIntent(action.actionCategory, action.targetPackage)
    }

    Card(
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (action.isUrgent)
                MaterialTheme.colorScheme.errorContainer
            else
                MaterialTheme.colorScheme.surface
        )
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = "${action.stepNumber}.",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(end = 8.dp)
                )
                Text(
                    text = action.title,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold
                )
            }

            if (action.description.isNotBlank()) {
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = action.description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            // CTA button if there's a resolvable intent
            if (intent != null) {
                Spacer(modifier = Modifier.height(8.dp))
                val canResolve = remember(intent) {
                    ActionIntentMapper.canResolve(context, intent)
                }
                Button(
                    onClick = {
                        if (canResolve) {
                            context.startActivity(intent)
                        }
                    },
                    enabled = canResolve,
                    colors = if (action.isUrgent)
                        ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
                    else
                        ButtonDefaults.buttonColors()
                ) {
                    Text(ActionIntentMapper.getActionLabel(action.actionCategory))
                }
            }
        }
    }
}

// ──────────────────────────────────────────────────────────
//  Technical details (Section 5 — collapsed)
// ──────────────────────────────────────────────────────────

@Composable
private fun TechnicalDetailsSection(tech: TechnicalDetailsModel) {
    var expanded by remember { mutableStateOf(false) }

    Card(
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Technické detaily",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )
                IconButton(onClick = { expanded = !expanded }) {
                    Icon(
                        imageVector = if (expanded) Icons.Default.KeyboardArrowUp
                        else Icons.Default.KeyboardArrowDown,
                        contentDescription = if (expanded) "Sbalit" else "Rozbalit"
                    )
                }
            }

            AnimatedVisibility(visible = expanded) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (tech.hypotheses.isNotEmpty()) {
                        DetailSubSection("Hypotézy", tech.hypotheses)
                    }
                    if (tech.signals.isNotEmpty()) {
                        DetailSubSection("Signály", tech.signals)
                    }
                    if (tech.affectedPackages.isNotEmpty()) {
                        DetailSubSection("Dotčené balíčky", tech.affectedPackages)
                    }
                    if (tech.metadata.isNotEmpty()) {
                        Text(
                            text = "Metadata",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.Bold
                        )
                        tech.metadata.forEach { (key, value) ->
                            Text(
                                text = "$key: $value",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun DetailSubSection(label: String, items: List<String>) {
    Text(
        text = label,
        style = MaterialTheme.typography.labelMedium,
        fontWeight = FontWeight.Bold
    )
    items.forEach { item ->
        Text(
            text = "• $item",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

// ──────────────────────────────────────────────────────────
//  Explanation section ("Vysvětlit" button + state)
// ──────────────────────────────────────────────────────────

@Composable
private fun ExplanationSection(
    state: ExplanationUiState,
    isBusyFallback: Boolean,
    engineSourceLabel: String?,
    onExplain: () -> Unit,
    onCancel: () -> Unit
) {
    Card(
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.secondaryContainer
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            when (state) {
                is ExplanationUiState.Idle -> {
                    Text(
                        text = "Chcete podrobnější vysvětlení od AI?",
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Button(onClick = onExplain) {
                        Text("Vysvětlit")
                    }
                }

                is ExplanationUiState.Loading -> {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        CircularProgressIndicator(modifier = Modifier.size(20.dp))
                        Text(
                            text = state.message,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedButton(onClick = onCancel) {
                        Text("Zrušit")
                    }
                }

                is ExplanationUiState.Ready -> {
                    Text(
                        text = "✅ Vysvětlení připraveno",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold
                    )
                    engineSourceLabel?.let { label ->
                        Text(
                            text = "Zdroj: $label",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.outline
                        )
                    }
                    if (isBusyFallback) {
                        Text(
                            text = "⚡ Šablonové vysvětlení (AI zaneprázdněná)",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.outline
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedButton(onClick = onExplain) {
                        Text("Vysvětlit znovu")
                    }
                }

                is ExplanationUiState.Error -> {
                    Text(
                        text = state.message,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Button(onClick = onExplain) {
                        Text("Zkusit znovu")
                    }
                }
            }
        }
    }
}
