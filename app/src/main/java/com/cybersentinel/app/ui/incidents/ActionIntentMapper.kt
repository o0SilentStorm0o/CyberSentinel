package com.cybersentinel.app.ui.incidents

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
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
 * Sprint UI-2: 7/10 — refined special access intents with metadata routing.
 */
object ActionIntentMapper {

    /**
     * Create an Android Intent for the given action category and target package.
     *
     * @param category The action type from the incident's recommended actions
     * @param targetPackage The package to act on (null for device-level actions)
     * @param metadata Optional metadata for context-sensitive routing
     * @return Intent ready to launch, or null if action is internal-only
     */
    fun createIntent(
        category: ActionCategory,
        targetPackage: String?,
        metadata: Map<String, String> = emptyMap()
    ): Intent? {
        return when (category) {
            ActionCategory.UNINSTALL -> {
                if (targetPackage == null) return null
                Intent(Intent.ACTION_DELETE, Uri.parse("package:$targetPackage"))
            }

            ActionCategory.DISABLE -> {
                createAppDetailsIntent(targetPackage) ?: openAppSettingsIntent()
            }

            ActionCategory.REVOKE_PERMISSION -> {
                createAppDetailsIntent(targetPackage) ?: openAppSettingsIntent()
            }

            ActionCategory.REVOKE_SPECIAL_ACCESS -> {
                // Route to the specific special access settings based on metadata
                createSpecialAccessIntent(targetPackage, metadata)
            }

            ActionCategory.CHECK_SETTINGS -> {
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
                @Suppress("DEPRECATION")
                Intent(Settings.ACTION_PRIVACY_SETTINGS).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                }
            }

            ActionCategory.MONITOR -> null
            ActionCategory.INFORM -> null
        }
    }

    /**
     * Route REVOKE_SPECIAL_ACCESS to the most specific Settings screen
     * based on which special access flags are active in metadata.
     *
     * Metadata keys (from EventRecorder → SpecialAccessSnapshot):
     *  - "accessibility" → ACTION_ACCESSIBILITY_SETTINGS
     *  - "notificationListener" → ACTION_NOTIFICATION_LISTENER_SETTINGS
     *  - "deviceAdmin" → ACTION_SECURITY_SETTINGS (device admin list)
     *  - "overlay" → ACTION_MANAGE_OVERLAY_PERMISSION (per-app on API 23+)
     *
     * If multiple are true, picks the most dangerous one first.
     */
    internal fun createSpecialAccessIntent(
        targetPackage: String?,
        metadata: Map<String, String>
    ): Intent {
        // Priority: overlay → accessibility → notification listener → device admin → generic
        return when {
            metadata["overlay"] == "true" && targetPackage != null -> {
                // Per-app overlay permission (API 23+)
                Intent(
                    Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                    Uri.parse("package:$targetPackage")
                ).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                }
            }

            metadata["accessibility"] == "true" -> {
                Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                }
            }

            metadata["notificationListener"] == "true" -> {
                Intent(NOTIFICATION_LISTENER_SETTINGS).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                }
            }

            metadata["deviceAdmin"] == "true" -> {
                // No per-app deep link for device admin; open security settings
                @Suppress("DEPRECATION")
                Intent(Settings.ACTION_SECURITY_SETTINGS).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                }
            }

            else -> {
                // Fallback: app details for the target package, or generic accessibility
                createAppDetailsIntent(targetPackage)
                    ?: Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS).apply {
                        flags = Intent.FLAG_ACTIVITY_NEW_TASK
                    }
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

    /**
     * Fallback instruction when canResolve() returns false — guides user manually.
     */
    fun getFallbackText(category: ActionCategory): String {
        return when (category) {
            ActionCategory.UNINSTALL -> "Otevřete Nastavení → Aplikace → vyberte aplikaci → Odinstalovat."
            ActionCategory.DISABLE -> "Otevřete Nastavení → Aplikace → vyberte aplikaci → Zakázat."
            ActionCategory.REVOKE_PERMISSION -> "Otevřete Nastavení → Aplikace → Oprávnění a zkontrolujte přístupy."
            ActionCategory.REVOKE_SPECIAL_ACCESS -> "Otevřete Nastavení → Speciální přístupy aplikací."
            ActionCategory.CHECK_SETTINGS -> "Otevřete Nastavení → Zabezpečení."
            ActionCategory.REINSTALL_FROM_STORE -> "Otevřete obchod Google Play a vyhledejte aplikaci."
            ActionCategory.FACTORY_RESET -> "Otevřete Nastavení → Systém → Obnovení továrního nastavení."
            ActionCategory.MONITOR -> "Sledujte chování aplikace v běžném provozu."
            ActionCategory.INFORM -> "Informujte se o tomto bezpečnostním problému."
        }
    }

    /** Settings constant for notification listener settings. */
    private const val NOTIFICATION_LISTENER_SETTINGS =
        "android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS"
}
