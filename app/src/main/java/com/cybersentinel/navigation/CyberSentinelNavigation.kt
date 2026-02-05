package com.cybersentinel.navigation

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.cybersentinel.app.ui.screens.appscan.AppScanScreen
import com.cybersentinel.app.ui.screens.dashboard.DashboardScreen
import com.cybersentinel.ui.screens.home.HomeScreen
import com.cybersentinel.ui.screens.qr.QrScannerScreen
import com.cybersentinel.ui.screens.wifi.WifiAuditorScreen
import com.cybersentinel.ui.screens.password.PasswordCheckScreen
import com.cybersentinel.ui.screens.settings.SettingsScreen

/**
 * Hlavní navigační komponenta aplikace CyberSentinel
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CyberSentinelNavigation(
    navController: NavHostController = rememberNavController()
) {
    Scaffold(
        bottomBar = {
            CyberSentinelBottomBar(navController = navController)
        }
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = Screen.Dashboard.route,
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            composable(Screen.Dashboard.route) {
                DashboardScreen()
            }
            
            composable(Screen.AppScan.route) {
                AppScanScreen(
                    onNavigateBack = { navController.popBackStack() }
                )
            }
            
            composable(Screen.Home.route) {
                HomeScreen()
            }
            
            composable(Screen.QrScanner.route) {
                QrScannerScreen()
            }
            
            composable(Screen.WifiAuditor.route) {
                WifiAuditorScreen()
            }
            
            composable(Screen.PasswordCheck.route) {
                PasswordCheckScreen()
            }
            
            composable(Screen.Settings.route) {
                SettingsScreen()
            }
        }
    }
}

/**
 * Bottom Navigation Bar komponenta
 */
@Composable
private fun CyberSentinelBottomBar(
    navController: NavHostController
) {
    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentDestination = navBackStackEntry?.destination

    NavigationBar {
        bottomNavScreens.forEach { screen ->
            NavigationBarItem(
                icon = {
                    Icon(
                        imageVector = screen.icon,
                        contentDescription = screen.title
                    )
                },
                label = {
                    Text(text = screen.title)
                },
                selected = currentDestination?.hierarchy?.any { it.route == screen.route } == true,
                onClick = {
                    navController.navigate(screen.route) {
                        // Pop up to the start destination of the graph to
                        // avoid building up a large stack of destinations
                        // on the back stack as users select items
                        popUpTo(navController.graph.findStartDestination().id) {
                            saveState = true
                        }
                        // Avoid multiple copies of the same destination when
                        // reselecting the same item
                        launchSingleTop = true
                        // Restore state when reselecting a previously selected item
                        restoreState = true
                    }
                }
            )
        }
    }
}