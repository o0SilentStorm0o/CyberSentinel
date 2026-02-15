package com.cybersentinel.app.ui.incidents

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import com.cybersentinel.app.domain.security.ActionCategory

/**
 * ActionIntentMapper — maps ActionCategory to Android Intents/Settings URIs.
 *
 * Each CTA button on the incident detail screen calls [createIntent] to get
 * the appropriate Intent. The UI launches it via `context.startActivity(intent)`.
 *
 * Fallback: If a specific deep-link doesn't exist on the device, falls back
 * to the most relevant Settings screen.
 *
 * Sprint UI-1: CTA mapping for action steps.
 */
object ActionIntentMapper {

    /**
     * Create an Android Intent for the given action category and target package.
     *
     * @param category The action type from the incident's recommended actions
     * @param targetPackage The package to act on (null for device-level actions)
     * @return Intent ready to launch, or null if action is internal-only
     */
    fun createIntent(category: ActionCategory, targetPackage: String?): Intent? {
        return when (category) {
            ActionCategory.UNINSTALL -> {
                if (targetPackage == null) return null
                Intent(Intent.ACTION_DELETE, Uri.parse("package:$targetPackage"))
            }

            ActionCategory.DISABLE -> {
                // Open app details where user can "Force Stop" / "Disable"
                createAppDetailsIntent(targetPackage) ?: openAppSettingsIntent()
            }

            ActionCategory.REVOKE_PERMISSION -> {
                // Android doesn't allow revoking permissions programmatically from another app.
                // Best we can do: open the app's details / permission screen.
                createAppDetailsIntent(targetPackage) ?: openAppSettingsIntent()
            }

            ActionCategory.REVOKE_SPECIAL_ACCESS -> {
                // Open the specific special access settings screen.
                // The user must navigate to the specific toggle.
                Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                }
            }

            ActionCategory.CHECK_SETTINGS -> {
                // Open security & privacy settings
                Intent(Settings.ACTION_SECURITY_SETTINGS).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                }
            }

            ActionCategory.REINSTALL_FROM_STORE -> {
                if (targetPackage == null) return null
                Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=$targetPackage")).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                }
            }

            ActionCategory.FACTORY_RESET -> {
                // NEVER do factory reset directly. Open the reset settings for user to decide.
                @Suppress("DEPRECATION")
                Intent(Settings.ACTION_PRIVACY_SETTINGS).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                }
            }

            ActionCategory.MONITOR -> {
                // Internal action — UI handles this (e.g., pin package for monitoring)
                null
            }

            ActionCategory.INFORM -> {
                // Internal action — UI shows info dialog, no system navigation
                null
            }
        }
    }

    /**
     * Create intent to open a specific app's detail settings page.
     */
    private fun createAppDetailsIntent(packageName: String?): Intent? {
        if (packageName == null) return null
        return Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
            data = Uri.parse("package:$packageName")
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
        }
    }

    /**
     * Fallback: open the general app list settings.
     */
    private fun openAppSettingsIntent(): Intent {
        return Intent(Settings.ACTION_APPLICATION_SETTINGS).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
        }
    }

    /**
     * Check if the intent is safe to launch (activity exists).
     */
    fun canResolve(context: Context, intent: Intent): Boolean {
        return intent.resolveActivity(context.packageManager) != null
    }

    /**
     * Human-readable CTA label for each action category (Czech).
     */
    fun getActionLabel(category: ActionCategory): String {
        return when (category) {
            ActionCategory.UNINSTALL -> "Odinstalovat"
            ActionCategory.DISABLE -> "Zakázat aplikaci"
            ActionCategory.REVOKE_PERMISSION -> "Zkontrolovat oprávnění"
            ActionCategory.REVOKE_SPECIAL_ACCESS -> "Zkontrolovat speciální přístupy"
            ActionCategory.CHECK_SETTINGS -> "Otevřít nastavení"
            ActionCategory.REINSTALL_FROM_STORE -> "Přeinstalovat z obchodu"
            ActionCategory.FACTORY_RESET -> "Nastavení zařízení"
            ActionCategory.MONITOR -> "Sledovat"
            ActionCategory.INFORM -> "Informace"
        }
    }
}
