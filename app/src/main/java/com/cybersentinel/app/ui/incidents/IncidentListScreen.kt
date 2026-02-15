package com.cybersentinel.app.ui.incidents

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.cybersentinel.app.domain.security.IncidentSeverity
import com.cybersentinel.app.domain.security.IncidentStatus

/**
 * Incident List Screen — displays all incidents sorted by severity + time.
 *
 * Sprint UI-1: Incident list MVP.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun IncidentListScreen(
    viewModel: IncidentListViewModel = hiltViewModel(),
    onIncidentClick: (eventId: String) -> Unit = {}
) {
    val ui by viewModel.ui.collectAsStateWithLifecycle()

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("Incidenty")
                        if (ui.activeCount > 0) {
                            Text(
                                text = "${ui.activeCount} aktivních",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                    }
                },
                actions = {
                    IconButton(onClick = { viewModel.loadIncidents() }) {
                        Icon(Icons.Default.Refresh, contentDescription = "Obnovit")
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
                        modifier = Modifier.align(Alignment.Center).padding(16.dp)
                    )
                }

                ui.incidents.isEmpty() -> {
                    EmptyIncidentState(modifier = Modifier.align(Alignment.Center))
                }

                else -> {
                    LazyColumn(
                        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        items(ui.incidents, key = { it.incidentId }) { card ->
                            IncidentCard(
                                card = card,
                                onClick = { onIncidentClick(card.incidentId) }
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun EmptyIncidentState(modifier: Modifier = Modifier) {
    Column(
        modifier = modifier.padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(
            imageVector = Icons.Default.Warning,
            contentDescription = null,
            modifier = Modifier.size(64.dp),
            tint = MaterialTheme.colorScheme.outline
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = "Žádné incidenty",
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.outline
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "Spusťte bezpečnostní sken pro detekci hrozeb.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.outline
        )
    }
}

@Composable
private fun IncidentCard(
    card: IncidentCardModel,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            // Top row: severity badge + status
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                SeverityBadge(card.severity)
                StatusChip(card.status)
            }

            Spacer(modifier = Modifier.height(8.dp))

            // Title
            Text(
                text = card.title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )

            Spacer(modifier = Modifier.height(4.dp))

            // Summary
            Text(
                text = card.shortSummary,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )

            // Affected packages
            if (card.displayPackages.isNotEmpty()) {
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    horizontalArrangement = Arrangement.spacedBy(4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    card.displayPackages.forEach { pkg ->
                        SuggestionChip(
                            onClick = {},
                            label = {
                                Text(
                                    text = pkg.substringAfterLast('.'),
                                    style = MaterialTheme.typography.labelSmall,
                                    maxLines = 1
                                )
                            }
                        )
                    }
                    card.overflowLabel?.let { overflow ->
                        Text(
                            text = overflow,
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.outline
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun SeverityBadge(severity: IncidentSeverity) {
    val color = when (severity) {
        IncidentSeverity.CRITICAL -> MaterialTheme.colorScheme.error
        IncidentSeverity.HIGH -> MaterialTheme.colorScheme.tertiary
        IncidentSeverity.MEDIUM -> MaterialTheme.colorScheme.secondary
        IncidentSeverity.LOW -> MaterialTheme.colorScheme.primary
        IncidentSeverity.INFO -> MaterialTheme.colorScheme.outline
    }
    Surface(
        shape = RoundedCornerShape(6.dp),
        color = color.copy(alpha = 0.15f)
    ) {
        Text(
            text = "${severity.emoji} ${severity.label}",
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Bold,
            color = color
        )
    }
}

@Composable
private fun StatusChip(status: IncidentStatus) {
    val label = when (status) {
        IncidentStatus.OPEN -> "Otevřený"
        IncidentStatus.INVESTIGATING -> "Vyšetřování"
        IncidentStatus.RESOLVED -> "Vyřešený"
        IncidentStatus.DISMISSED -> "Zamítnutý"
        IncidentStatus.FALSE_POSITIVE -> "Falešný poplach"
    }
    Text(
        text = label,
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.outline
    )
}
