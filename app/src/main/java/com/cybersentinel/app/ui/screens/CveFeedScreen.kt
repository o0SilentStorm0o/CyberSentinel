package com.cybersentinel.app.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Done
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun CveFeedScreen(vm: CveViewModel = hiltViewModel()) {
    val uiState by vm.ui.collectAsState()
    val relevantOnly by vm.relevantOnly.collectAsState()
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("CVE Feed") },
                actions = {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(end = 8.dp)
                    ) {
                        Text("Relevant", style = MaterialTheme.typography.bodyMedium)
                        Spacer(Modifier.width(8.dp))
                        Switch(
                            checked = relevantOnly,
                            onCheckedChange = vm::toggleRelevant
                        )
                    }
                }
            )
        }
    ) { paddingValues ->
        if (uiState.loading && uiState.items.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(paddingValues),
                contentAlignment = Alignment.Center
            ) {
                CircularProgressIndicator()
            }
        } else {
            LazyColumn(
                modifier = Modifier.padding(paddingValues),
                contentPadding = PaddingValues(vertical = 8.dp)
            ) {
                item {
                    HistoryChips(
                        selected = uiState.daysBack,
                        onSelect = vm::setDaysBack,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)
                    )
                }
                
                items(uiState.items, key = { it.item.id }) { relevantCve ->
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 8.dp)
                    ) {
                        // Header s ID a score
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = relevantCve.item.id,
                                style = MaterialTheme.typography.titleMedium,
                                color = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.weight(1f)
                            )
                            Row(
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                if (relevantCve.score > 0) {
                                    AssistChip(
                                        onClick = { },
                                        label = { Text("Score: ${relevantCve.score}") }
                                    )
                                }
                                IconButton(onClick = { vm.acknowledge(relevantCve.item.id) }) { 
                                    Icon(
                                        imageVector = Icons.Outlined.Done, 
                                        contentDescription = "Mark as read"
                                    ) 
                                }
                            }
                        }
                        
                        Spacer(Modifier.height(4.dp))
                        
                        // Summary
                        Text(
                            text = relevantCve.item.summary,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        
                        // Tags
                        if (relevantCve.tags.isNotEmpty()) {
                            Spacer(Modifier.height(8.dp))
                            FlowRow(
                                horizontalArrangement = Arrangement.spacedBy(6.dp),
                                verticalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
                                relevantCve.tags.forEach { tag ->
                                    AssistChip(
                                        onClick = { },
                                        label = { 
                                            Text(
                                                text = tag,
                                                style = MaterialTheme.typography.labelSmall
                                            ) 
                                        }
                                    )
                                }
                            }
                        }
                    }
                    
                    HorizontalDivider(
                        modifier = Modifier.padding(horizontal = 16.dp),
                        color = MaterialTheme.colorScheme.outlineVariant
                    )
                }
                
                if (uiState.canLoadMore) {
                    item {
                        LoadMoreButton(
                            loading = uiState.loading,
                            onClick = vm::loadMore
                        )
                    }
                }
                
                if (uiState.error != null) {
                    item {
                        ErrorCard(
                            message = uiState.error ?: "Unknown error",
                            onRetry = vm::refresh
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun HistoryChips(
    selected: Int,
    onSelect: (Int) -> Unit,
    modifier: Modifier = Modifier
) {
    val options = listOf(7, 30, 90, 365)
    val labels = listOf("7d", "30d", "90d", "120d*") // Ukazuje skutečný NVD limit
    
    LazyRow(
        modifier = modifier,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        items(options.zip(labels)) { (days, label) ->
            FilterChip(
                selected = selected == days,
                onClick = { onSelect(days) },
                label = { Text(label) }
            )
        }
    }
}

@Composable
private fun LoadMoreButton(
    loading: Boolean,
    onClick: () -> Unit
) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        contentAlignment = Alignment.Center
    ) {
        if (loading) {
            CircularProgressIndicator(modifier = Modifier.size(24.dp))
        } else {
            OutlinedButton(onClick = onClick) {
                Text("Načíst další")
            }
        }
    }
}

@Composable
private fun ErrorCard(
    message: String,
    onRetry: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = "Chyba",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onErrorContainer
            )
            Text(
                text = message,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onErrorContainer
            )
            OutlinedButton(
                onClick = onRetry,
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = MaterialTheme.colorScheme.onErrorContainer
                )
            ) {
                Text("Zkusit znovu")
            }
        }
    }
}