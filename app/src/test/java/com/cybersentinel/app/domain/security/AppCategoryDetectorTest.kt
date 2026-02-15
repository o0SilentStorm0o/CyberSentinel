package com.cybersentinel.app.domain.security

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for AppCategoryDetector.
 *
 * Coverage:
 *  - All 16 categories detected by package/app name
 *  - Expected permission mapping
 *  - Unexpected permission detection
 *  - Edge cases: unknown apps, mixed signals
 */
class AppCategoryDetectorTest {

    // ══════════════════════════════════════════════════════════
    //  Category detection by package name
    // ══════════════════════════════════════════════════════════

    @Test
    fun `detect BANKING from package name`() {
        assertEquals(
            AppCategoryDetector.AppCategory.BANKING,
            AppCategoryDetector.detectCategory("cz.csob.smartbanking", "ČSOB Smart")
        )
        assertEquals(
            AppCategoryDetector.AppCategory.BANKING,
            AppCategoryDetector.detectCategory("com.fio.ib2", "Fio Banka")
        )
    }

    @Test
    fun `detect MESSAGING from package name`() {
        assertEquals(
            AppCategoryDetector.AppCategory.MESSAGING,
            AppCategoryDetector.detectCategory("com.whatsapp", "WhatsApp")
        )
        assertEquals(
            AppCategoryDetector.AppCategory.MESSAGING,
            AppCategoryDetector.detectCategory("org.telegram.messenger", "Telegram")
        )
    }

    @Test
    fun `detect SOCIAL from package name`() {
        assertEquals(
            AppCategoryDetector.AppCategory.SOCIAL,
            AppCategoryDetector.detectCategory("com.instagram.android", "Instagram")
        )
        assertEquals(
            AppCategoryDetector.AppCategory.SOCIAL,
            AppCategoryDetector.detectCategory("com.twitter.android", "X")
        )
    }

    @Test
    fun `detect NAVIGATION from package name`() {
        assertEquals(
            AppCategoryDetector.AppCategory.NAVIGATION,
            AppCategoryDetector.detectCategory("com.google.android.apps.maps", "Maps")
        )
        assertEquals(
            AppCategoryDetector.AppCategory.NAVIGATION,
            AppCategoryDetector.detectCategory("com.waze", "Waze")
        )
    }

    @Test
    fun `detect CAMERA from package name`() {
        assertEquals(
            AppCategoryDetector.AppCategory.CAMERA,
            AppCategoryDetector.detectCategory("com.google.android.camera", "Camera")
        )
    }

    @Test
    fun `detect BROWSER from package name`() {
        assertEquals(
            AppCategoryDetector.AppCategory.BROWSER,
            AppCategoryDetector.detectCategory("com.android.chrome", "Chrome")
        )
        assertEquals(
            AppCategoryDetector.AppCategory.BROWSER,
            AppCategoryDetector.detectCategory("org.mozilla.firefox", "Firefox")
        )
    }

    @Test
    fun `detect PHONE_DIALER from package name`() {
        assertEquals(
            AppCategoryDetector.AppCategory.PHONE_DIALER,
            AppCategoryDetector.detectCategory("com.google.android.dialer", "Phone")
        )
        assertEquals(
            AppCategoryDetector.AppCategory.PHONE_DIALER,
            AppCategoryDetector.detectCategory("com.android.contacts", "Contacts")
        )
    }

    @Test
    fun `detect VPN from package name`() {
        assertEquals(
            AppCategoryDetector.AppCategory.VPN,
            AppCategoryDetector.detectCategory("com.nordvpn.android", "NordVPN")
        )
        assertEquals(
            AppCategoryDetector.AppCategory.VPN,
            AppCategoryDetector.detectCategory("com.wireguard.android", "WireGuard")
        )
    }

    @Test
    fun `detect SECURITY from package name`() {
        assertEquals(
            AppCategoryDetector.AppCategory.SECURITY,
            AppCategoryDetector.detectCategory("com.cybersentinel.app", "CyberSentinel")
        )
    }

    @Test
    fun `detect LAUNCHER from package name`() {
        assertEquals(
            AppCategoryDetector.AppCategory.LAUNCHER,
            AppCategoryDetector.detectCategory("com.teslacoilsw.launcher", "Nova Launcher")
        )
    }

    @Test
    fun `detect ACCESSIBILITY_TOOL from package name`() {
        assertEquals(
            AppCategoryDetector.AppCategory.ACCESSIBILITY_TOOL,
            AppCategoryDetector.detectCategory("com.google.android.marvin.talkback", "TalkBack")
        )
    }

    @Test
    fun `detect KEYBOARD from package name`() {
        assertEquals(
            AppCategoryDetector.AppCategory.KEYBOARD,
            AppCategoryDetector.detectCategory("com.google.android.inputmethod.gboard", "Gboard")
        )
        assertEquals(
            AppCategoryDetector.AppCategory.KEYBOARD,
            AppCategoryDetector.detectCategory("com.touchtype.swiftkey", "SwiftKey")
        )
    }

    @Test
    fun `detect FITNESS from package name`() {
        assertEquals(
            AppCategoryDetector.AppCategory.FITNESS,
            AppCategoryDetector.detectCategory("com.strava", "Strava")
        )
    }

    @Test
    fun `detect GAME from package name`() {
        assertEquals(
            AppCategoryDetector.AppCategory.GAME,
            AppCategoryDetector.detectCategory("com.supercell.game.clashofclans", "Clash of Clans")
        )
    }

    @Test
    fun `detect UTILITY from package name`() {
        assertEquals(
            AppCategoryDetector.AppCategory.UTILITY,
            AppCategoryDetector.detectCategory("com.android.calculator2", "Calculator")
        )
        assertEquals(
            AppCategoryDetector.AppCategory.UTILITY,
            AppCategoryDetector.detectCategory("com.example.flashlight", "Flashlight")
        )
    }

    @Test
    fun `detect OTHER for unknown apps`() {
        assertEquals(
            AppCategoryDetector.AppCategory.OTHER,
            AppCategoryDetector.detectCategory("com.totally.unknown.xyz", "Random App")
        )
    }

    // ══════════════════════════════════════════════════════════
    //  Detection by app name (when package is generic)
    // ══════════════════════════════════════════════════════════

    @Test
    fun `detect from Czech app name`() {
        assertEquals(
            AppCategoryDetector.AppCategory.UTILITY,
            AppCategoryDetector.detectCategory("com.example.app", "Kalkulačka")
        )
        assertEquals(
            AppCategoryDetector.AppCategory.UTILITY,
            AppCategoryDetector.detectCategory("com.example.app", "Svítilna")
        )
    }

    @Test
    fun `detect VPN from app name`() {
        assertEquals(
            AppCategoryDetector.AppCategory.VPN,
            AppCategoryDetector.detectCategory("com.example.app", "Super VPN Free")
        )
    }

    // ══════════════════════════════════════════════════════════
    //  Expected permission mapping
    // ══════════════════════════════════════════════════════════

    @Test
    fun `CAMERA permission is expected for camera apps`() {
        assertTrue(
            AppCategoryDetector.isPermissionExpected(
                AppCategoryDetector.AppCategory.CAMERA,
                "android.permission.CAMERA"
            )
        )
    }

    @Test
    fun `SMS permission is expected for phone dialer`() {
        assertTrue(
            AppCategoryDetector.isPermissionExpected(
                AppCategoryDetector.AppCategory.PHONE_DIALER,
                "android.permission.READ_SMS"
            )
        )
    }

    @Test
    fun `SMS permission is NOT expected for banking`() {
        assertFalse(
            AppCategoryDetector.isPermissionExpected(
                AppCategoryDetector.AppCategory.BANKING,
                "android.permission.READ_SMS"
            )
        )
    }

    @Test
    fun `VPN service is expected for VPN apps`() {
        assertTrue(
            AppCategoryDetector.isPermissionExpected(
                AppCategoryDetector.AppCategory.VPN,
                "android.permission.BIND_VPN_SERVICE"
            )
        )
    }

    @Test
    fun `background location is expected for navigation`() {
        assertTrue(
            AppCategoryDetector.isPermissionExpected(
                AppCategoryDetector.AppCategory.NAVIGATION,
                "android.permission.ACCESS_BACKGROUND_LOCATION"
            )
        )
    }

    @Test
    fun `GAME and UTILITY have no expected permissions`() {
        assertTrue(AppCategoryDetector.AppCategory.GAME.expectedPermissions.isEmpty())
        assertTrue(AppCategoryDetector.AppCategory.UTILITY.expectedPermissions.isEmpty())
    }

    // ══════════════════════════════════════════════════════════
    //  Unexpected permission detection
    // ══════════════════════════════════════════════════════════

    @Test
    fun `getUnexpectedPermissions filters out expected ones`() {
        val unexpected = AppCategoryDetector.getUnexpectedPermissions(
            AppCategoryDetector.AppCategory.CAMERA,
            listOf(
                "android.permission.CAMERA",         // expected
                "android.permission.READ_SMS",        // NOT expected
                "android.permission.RECORD_AUDIO"     // expected
            )
        )
        assertEquals(1, unexpected.size)
        assertEquals("android.permission.READ_SMS", unexpected[0])
    }

    @Test
    fun `getUnexpectedPermissions returns all for OTHER category`() {
        val perms = listOf(
            "android.permission.CAMERA",
            "android.permission.READ_SMS"
        )
        val unexpected = AppCategoryDetector.getUnexpectedPermissions(
            AppCategoryDetector.AppCategory.OTHER,
            perms
        )
        assertEquals("OTHER has no expected perms, so all should be unexpected", 2, unexpected.size)
    }

    @Test
    fun `getUnexpectedPermissions returns empty for matching category`() {
        val unexpected = AppCategoryDetector.getUnexpectedPermissions(
            AppCategoryDetector.AppCategory.MESSAGING,
            listOf(
                "android.permission.CAMERA",
                "android.permission.READ_CONTACTS",
                "android.permission.RECORD_AUDIO"
            )
        )
        assertEquals("All perms are expected for messaging", 0, unexpected.size)
    }

    // ══════════════════════════════════════════════════════════
    //  Category labels
    // ══════════════════════════════════════════════════════════

    @Test
    fun `all categories have Czech labels`() {
        AppCategoryDetector.AppCategory.entries.forEach { category ->
            assertTrue(
                "Category ${category.name} should have a non-empty label",
                category.label.isNotBlank()
            )
        }
    }

    @Test
    fun `category count is 20`() {
        assertEquals(20, AppCategoryDetector.AppCategory.entries.size)
    }
}
