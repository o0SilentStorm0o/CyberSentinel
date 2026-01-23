package com.cybersentinel.ui.screens.home

import androidx.compose.runtime.Composable
import androidx.hilt.navigation.compose.hiltViewModel
import com.cybersentinel.app.ui.screens.CveFeedScreen
import com.cybersentinel.app.ui.screens.CveViewModel

/**
 * Home screen - obsahuje CVE Monitor
 */
@Composable
fun HomeScreen(
    cveViewModel: CveViewModel = hiltViewModel()
) {
    CveFeedScreen(vm = cveViewModel)
}