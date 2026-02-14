package com.cybersentinel.app.domain.explainability

import com.cybersentinel.app.domain.security.ActionCategory
import com.cybersentinel.app.domain.security.EventType
import com.cybersentinel.app.domain.security.Hypothesis
import com.cybersentinel.app.domain.security.IncidentSeverity
import com.cybersentinel.app.domain.security.RecommendedAction
import com.cybersentinel.app.domain.security.SecurityIncident
import com.cybersentinel.app.domain.security.SignalSeverity
import javax.inject.Inject
import javax.inject.Singleton

/**
 * TemplateExplanationEngine — deterministic Czech template engine.
 *
 * This is NOT a "dumb fallback". It is the BASELINE QUALITY engine:
 *  1. Ground truth for measuring future LLM quality
 *  2. Renders LLM structured slots into Czech (LLM fills slots → this renders)
 *  3. Always-available engine for TIER_0 devices and runtime gate fallback
 *
 * Architecture:
 *  - Maps IncidentSeverity + EventType + Hypothesis.name → Czech template
 *  - Applies PolicyGuard constraints before rendering
 *  - Produces the same ExplanationAnswer schema as LLM engine
 *
 * Templates are organized by:
 *  1. Event type → summary templates + reason templates
 *  2. Action category → action step templates
 *  3. Severity → whenToIgnore templates
 *
 * All Czech text is in this file — single source of truth for localization.
 * Thread safety: Stateless, safe for concurrent use.
 */
@Singleton
class TemplateExplanationEngine @Inject constructor(
    private val policyGuard: PolicyGuard
) : ExplanationEngine {

    override val engineId: String = "template-v1"

    override val isAvailable: Boolean = true

    // ══════════════════════════════════════════════════════════
    //  Main entry point
    // ══════════════════════════════════════════════════════════

    override fun explain(request: ExplanationRequest): ExplanationAnswer {
        val incident = request.incident
        val constraints = policyGuard.determineConstraints(incident)

        // 1. Build summary from event types and severity
        val summary = buildSummary(incident, constraints)

        // 2. Build evidence reasons from hypotheses + signals
        val reasons = buildReasons(incident, constraints)

        // 3. Build action steps from recommended actions
        val actions = buildActions(incident, constraints)

        // 4. Build whenToIgnore guidance
        val whenToIgnore = buildWhenToIgnore(incident)

        // 5. Calculate confidence (template engine = deterministic, so confidence = top hypothesis)
        val confidence = incident.hypotheses.maxOfOrNull { it.confidence } ?: 0.5

        // 6. Assemble raw answer
        val rawAnswer = ExplanationAnswer(
            incidentId = incident.id,
            severity = incident.severity,
            summary = summary,
            reasons = reasons,
            actions = actions,
            whenToIgnore = whenToIgnore,
            confidence = confidence,
            engineSource = EngineSource.TEMPLATE
        )

        // 7. PolicyGuard post-validation (catches any remaining violations)
        return policyGuard.validate(rawAnswer, incident)
    }

    /**
     * Render an ExplanationAnswer from LLM structured slots.
     *
     * The LLM fills structured decisions (severity, evidence selection, actions).
     * This method renders those decisions into Czech using the same templates.
     *
     * Used by future LlmExplanationEngine in Sprint C.
     */
    fun renderFromSlots(
        slots: LlmStructuredSlots,
        incident: SecurityIncident
    ): ExplanationAnswer {
        val constraints = policyGuard.determineConstraints(incident)

        // Use LLM's evidence selection to build reasons (filtered by what exists)
        val allSignals = incident.events.flatMap { it.signals }
        val selectedSignals = allSignals.filter { it.id in slots.selectedEvidenceIds }

        val reasons = selectedSignals.mapIndexed { idx, signal ->
            val findingType = PolicyGuard.signalTypeToFindingType[signal.type]
            val isHard = findingType?.hardness == com.cybersentinel.app.domain.security.TrustRiskModel.FindingHardness.HARD
            EvidenceReason(
                evidenceId = signal.id,
                text = signalReasonTemplates[signal.type.name] ?: signal.summary,
                severity = mapSignalSeverityToIncident(signal.severity),
                findingTag = signal.type.name,
                isHardEvidence = isHard
            )
        }

        val actions = slots.recommendedActions
            .filter { policyGuard.isActionAllowed(it, constraints) }
            .mapIndexed { idx, category ->
                ActionStep(
                    stepNumber = idx + 1,
                    actionCategory = category,
                    title = actionTitleTemplates[category] ?: category.name,
                    description = actionDescriptionTemplates[category]
                        ?.replace("{package}", incident.packageName ?: "aplikace")
                        ?: "Proveďte doporučenou akci.",
                    targetPackage = incident.packageName,
                    isUrgent = category in setOf(ActionCategory.UNINSTALL, ActionCategory.FACTORY_RESET)
                )
            }

        val whenToIgnore = if (slots.canBeIgnored) {
            ignoreReasonTemplates[slots.ignoreReasonKey] ?: buildWhenToIgnore(incident)
        } else null

        val primaryEventType = incident.events.firstOrNull()?.type
        val summary = summaryTemplates[primaryEventType]
            ?.replace("{package}", incident.packageName ?: "aplikace")
            ?.replace("{severity}", slots.assessedSeverity.label)
            ?: incident.summary

        val rawAnswer = ExplanationAnswer(
            incidentId = incident.id,
            severity = slots.assessedSeverity,
            summary = summary,
            reasons = reasons,
            actions = actions,
            whenToIgnore = whenToIgnore,
            confidence = slots.confidence,
            engineSource = EngineSource.LLM_ASSISTED
        )

        return policyGuard.validate(rawAnswer, incident)
    }

    // ══════════════════════════════════════════════════════════
    //  Summary builder
    // ══════════════════════════════════════════════════════════

    private fun buildSummary(
        incident: SecurityIncident,
        constraints: Set<SafeLanguageFlag>
    ): String {
        val packageLabel = incident.packageName ?: "aplikace"
        val primaryEventType = incident.events.firstOrNull()?.type

        // Start with event-type-specific template
        var summary = summaryTemplates[primaryEventType]
            ?.replace("{package}", packageLabel)
            ?.replace("{severity}", incident.severity.label)
            ?: "Bezpečnostní nález pro $packageLabel (${incident.severity.label})."

        // Apply severity prefix
        summary = when (incident.severity) {
            IncidentSeverity.CRITICAL -> "${incident.severity.emoji} $summary"
            IncidentSeverity.HIGH -> "${incident.severity.emoji} $summary"
            else -> summary
        }

        return summary
    }

    // ══════════════════════════════════════════════════════════
    //  Reason builder
    // ══════════════════════════════════════════════════════════

    private fun buildReasons(
        incident: SecurityIncident,
        constraints: Set<SafeLanguageFlag>
    ): List<EvidenceReason> {
        val reasons = mutableListOf<EvidenceReason>()

        // 1. From hypotheses (primary source)
        for (hypothesis in incident.hypotheses.sortedByDescending { it.confidence }) {
            val templateText = hypothesisReasonTemplates[hypothesis.name]
            if (templateText != null) {
                val evidenceId = hypothesis.supportingEvidence.firstOrNull() ?: incident.id
                reasons.add(
                    EvidenceReason(
                        evidenceId = evidenceId,
                        text = templateText.replace("{package}", incident.packageName ?: "aplikace")
                            .replace("{confidence}", formatConfidence(hypothesis.confidence)),
                        severity = confidenceToSeverity(hypothesis.confidence),
                        findingTag = hypothesis.name,
                        isHardEvidence = hypothesis.confidence >= 0.7
                    )
                )
            }
        }

        // 2. From signals (supplement if hypotheses don't cover all signals)
        val coveredTags = reasons.map { it.findingTag }.toSet()
        for (event in incident.events) {
            for (signal in event.signals) {
                if (signal.type.name !in coveredTags) {
                    val templateText = signalReasonTemplates[signal.type.name]
                    if (templateText != null) {
                        val findingType = PolicyGuard.signalTypeToFindingType[signal.type]
                        val isHard = findingType?.hardness ==
                            com.cybersentinel.app.domain.security.TrustRiskModel.FindingHardness.HARD
                        reasons.add(
                            EvidenceReason(
                                evidenceId = signal.id,
                                text = templateText.replace("{package}", incident.packageName ?: "aplikace"),
                                severity = mapSignalSeverityToIncident(signal.severity),
                                findingTag = signal.type.name,
                                isHardEvidence = isHard
                            )
                        )
                    }
                }
            }
        }

        // Sort: HARD evidence first, then by severity
        return reasons.sortedWith(
            compareByDescending<EvidenceReason> { it.isHardEvidence }
                .thenByDescending { it.severity.ordinal }
        )
    }

    // ══════════════════════════════════════════════════════════
    //  Action builder
    // ══════════════════════════════════════════════════════════

    private fun buildActions(
        incident: SecurityIncident,
        constraints: Set<SafeLanguageFlag>
    ): List<ActionStep> {
        return incident.recommendedActions
            .sortedBy { it.priority }
            .filter { policyGuard.isActionAllowed(it.type, constraints) }
            .mapIndexed { idx, action ->
                ActionStep(
                    stepNumber = idx + 1,
                    actionCategory = action.type,
                    title = actionTitleTemplates[action.type] ?: action.title,
                    description = renderActionDescription(action, incident.packageName),
                    targetPackage = action.targetPackage ?: incident.packageName,
                    isUrgent = action.type in setOf(
                        ActionCategory.UNINSTALL,
                        ActionCategory.FACTORY_RESET
                    )
                )
            }
    }

    private fun renderActionDescription(
        action: RecommendedAction,
        packageName: String?
    ): String {
        val packageLabel = packageName ?: "aplikace"
        return actionDescriptionTemplates[action.type]
            ?.replace("{package}", packageLabel)
            ?: action.description
    }

    // ══════════════════════════════════════════════════════════
    //  WhenToIgnore builder
    // ══════════════════════════════════════════════════════════

    private fun buildWhenToIgnore(incident: SecurityIncident): String? {
        return when (incident.severity) {
            IncidentSeverity.INFO ->
                "Tento nález je pouze informační. Pokud aplikaci znáte a důvěřujete jí, " +
                    "není třeba žádná akce."
            IncidentSeverity.LOW ->
                "Nízká závažnost. Pokud jste aplikaci nainstalovali záměrně z důvěryhodného zdroje, " +
                    "můžete tento nález ignorovat."
            IncidentSeverity.MEDIUM ->
                "Zkontrolujte doporučené kroky. Pokud jste změny provedli sami " +
                    "(např. ruční aktualizace, sideload z APKMirror), je to pravděpodobně v pořádku."
            IncidentSeverity.HIGH, IncidentSeverity.CRITICAL ->
                null  // Never suggest ignoring HIGH/CRITICAL
        }
    }

    // ══════════════════════════════════════════════════════════
    //  Helper functions
    // ══════════════════════════════════════════════════════════

    private fun confidenceToSeverity(confidence: Double): IncidentSeverity = when {
        confidence >= 0.8 -> IncidentSeverity.CRITICAL
        confidence >= 0.6 -> IncidentSeverity.HIGH
        confidence >= 0.4 -> IncidentSeverity.MEDIUM
        confidence >= 0.2 -> IncidentSeverity.LOW
        else -> IncidentSeverity.INFO
    }

    private fun formatConfidence(confidence: Double): String =
        "${(confidence * 100).toInt()}%"

    private fun mapSignalSeverityToIncident(severity: SignalSeverity): IncidentSeverity = when (severity) {
        SignalSeverity.CRITICAL -> IncidentSeverity.CRITICAL
        SignalSeverity.HIGH -> IncidentSeverity.HIGH
        SignalSeverity.MEDIUM -> IncidentSeverity.MEDIUM
        SignalSeverity.LOW -> IncidentSeverity.LOW
        SignalSeverity.INFO -> IncidentSeverity.INFO
    }

    // ══════════════════════════════════════════════════════════
    //  Czech template tables
    // ══════════════════════════════════════════════════════════

    companion object {

        // ── Summary templates by EventType ──
        val summaryTemplates: Map<EventType, String> = mapOf(
            EventType.SUSPICIOUS_UPDATE to
                "Aplikace {package} byla aktualizována s podezřelými změnami.",
            EventType.SUSPICIOUS_INSTALL to
                "Nově nainstalovaná aplikace {package} vykazuje podezřelé vlastnosti.",
            EventType.CAPABILITY_ESCALATION to
                "Aplikace {package} získala nová nebezpečná oprávnění.",
            EventType.SPECIAL_ACCESS_GRANT to
                "Aplikace {package} získala speciální přístup k systému.",
            EventType.STALKERWARE_PATTERN to
                "Aplikace {package} odpovídá vzoru sledovacího softwaru.",
            EventType.DROPPER_PATTERN to
                "Aplikace {package} odpovídá vzoru dropper malwaru.",
            EventType.OVERLAY_ATTACK_PATTERN to
                "Aplikace {package} může provádět overlay útok.",
            EventType.CONFIG_TAMPER to
                "Bylo detekováno podezřelé nastavení zařízení.",
            EventType.CA_CERT_INSTALLED to
                "Byl nainstalován nový CA certifikát — možné odposlouchávání šifrované komunikace.",
            EventType.SUSPICIOUS_VPN to
                "VPN aktivována podezřelou aplikací — provoz může být přesměrován.",
            EventType.DEVICE_COMPROMISE to
                "Detekován problém s integritou zařízení.",
            EventType.BEHAVIORAL_ANOMALY to
                "Aplikace {package} vykazuje neobvyklé chování.",
            EventType.OTHER to
                "Bezpečnostní nález pro {package}."
        )

        // ── Hypothesis reason templates (keyed by hypothesis.name) ──
        val hypothesisReasonTemplates: Map<String, String> = mapOf(
            // Stalkerware
            "confirmed_stalkerware" to
                "Aplikace {package} má kombinaci oprávnění typickou pro sledovací software (důvěra: {confidence}).",
            "possible_stalkerware" to
                "Aplikace {package} vykazuje znaky sledovacího softwaru, ale bez plného potvrzení (důvěra: {confidence}).",
            "stalkerware_surveillance" to
                "Aplikace {package} má přístup ke kameře, mikrofonu a poloze s možností skrytého běhu (důvěra: {confidence}).",

            // Dropper
            "dropper_pattern" to
                "Aplikace {package} odpovídá vzoru dropper malwaru — instalátor s přístupem k přístupnosti (důvěra: {confidence}).",
            "possible_dropper" to
                "Aplikace {package} může být dropper — má instalační oprávnění a přístup k přístupnosti (důvěra: {confidence}).",

            // Update/change
            "malicious_update" to
                "Aktualizace aplikace {package} přidala nebezpečná oprávnění — možná kompromitace dodavatelského řetězce (důvěra: {confidence}).",
            "suspicious_update" to
                "Aktualizace aplikace {package} změnila bezpečnostní profil — vyžaduje kontrolu (důvěra: {confidence}).",
            "supply_chain_compromise" to
                "Podezření na kompromitaci dodavatelského řetězce — certifikát nebo instalátor se změnil (důvěra: {confidence}).",

            // Escalation
            "capability_escalation" to
                "Aplikace {package} získala nová nebezpečná oprávnění bez zjevného důvodu (důvěra: {confidence}).",
            "privilege_abuse" to
                "Aplikace {package} má nadměrná oprávnění pro svou kategorii (důvěra: {confidence}).",

            // Special access
            "special_access_abuse" to
                "Speciální přístup (přístupnost, notifikace) umožňuje aplikaci {package} číst obsah jiných aplikací (důvěra: {confidence}).",
            "accessibility_abuse" to
                "Služba přístupnosti může aplikaci {package} umožnit zachytávat klávesové vstupy a ovládat obrazovku (důvěra: {confidence}).",

            // Config
            "mitm_attack" to
                "Nainstalovaný CA certifikát může umožnit odposlech šifrované komunikace (důvěra: {confidence}).",
            "config_tampering" to
                "Nastavení zařízení bylo změněno způsobem, který může ohrozit bezpečnost (důvěra: {confidence}).",
            "dns_hijack" to
                "Nastavení DNS bylo změněno — provoz může být přesměrován (důvěra: {confidence}).",

            // Overlay
            "overlay_phishing" to
                "Aplikace {package} může zobrazovat překryvné vrstvy přes jiné aplikace — riziko phishingu (důvěra: {confidence}).",

            // Device
            "device_rooted" to
                "Zařízení je rootované — bezpečnostní model Androidu je oslaben (důvěra: {confidence}).",
            "bootloader_unlocked" to
                "Bootloader je odemčený — systém může být modifikován (důvěra: {confidence}).",

            // Generic fallbacks
            "generic_risk" to
                "Aplikace {package} vykazuje bezpečnostní riziko vyžadující pozornost (důvěra: {confidence}).",
            "unknown" to
                "Detekován bezpečnostní nález pro {package} (důvěra: {confidence})."
        )

        // ── Signal reason templates (keyed by SignalType.name) ──
        val signalReasonTemplates: Map<String, String> = mapOf(
            "CERT_CHANGE" to "Podpisový certifikát aplikace {package} se změnil — může jít o podvrženou verzi.",
            "VERSION_ROLLBACK" to "Verze aplikace {package} byla snížena — možný downgrade útok.",
            "INSTALLER_CHANGE" to "Zdroj instalace aplikace {package} se změnil — neobvyklá aktualizace.",
            "HIGH_RISK_PERM_ADDED" to "Aplikace {package} získala nové vysoce rizikové oprávnění.",
            "SPECIAL_ACCESS_ENABLED" to "Aplikace {package} získala speciální přístup (přístupnost/notifikace).",
            "SPECIAL_ACCESS_DISABLED" to "Speciální přístup aplikace {package} byl odebrán.",
            "EXPORTED_SURFACE_CHANGE" to "Aplikace {package} zvýšila počet exportovaných komponent.",
            "NEW_APP_INSTALLED" to "Nová aplikace {package} byla nainstalována.",
            "SUSPICIOUS_NATIVE_LIB" to "Aplikace {package} obsahuje podezřelé nativní knihovny.",
            "DEBUG_SIGNATURE" to "Aplikace {package} je podepsána debug certifikátem — neměla by být na produkčním zařízení.",
            "COMBO_DETECTED" to "Kombinace oprávnění aplikace {package} odpovídá známému nebezpečnému vzoru.",
            "USER_CA_CERT_ADDED" to "Nový uživatelský CA certifikát — šifrovaná komunikace může být odposlouchávána.",
            "USER_CA_CERT_REMOVED" to "Uživatelský CA certifikát byl odebrán.",
            "PRIVATE_DNS_CHANGED" to "Nastavení privátního DNS se změnilo.",
            "VPN_STATE_CHANGED" to "Stav VPN se změnil.",
            "UNKNOWN_ACCESSIBILITY_SERVICE" to "Neznámá služba přístupnosti je aktivní.",
            "DEFAULT_APP_CHANGED" to "Výchozí aplikace (SMS/telefon) byla změněna.",
            "ROOT_DETECTED" to "Na zařízení byl detekován root přístup.",
            "BOOTLOADER_UNLOCKED" to "Bootloader zařízení je odemčený.",
            "DEVELOPER_OPTIONS_ENABLED" to "Vývojářské možnosti jsou zapnuty.",
            "USB_DEBUGGING_ENABLED" to "USB ladění je zapnuto — zařízení je přístupné přes ADB."
        )

        // ── Action title templates ──
        val actionTitleTemplates: Map<ActionCategory, String> = mapOf(
            ActionCategory.UNINSTALL to "Odinstalovat aplikaci",
            ActionCategory.DISABLE to "Zakázat aplikaci",
            ActionCategory.REVOKE_PERMISSION to "Odebrat oprávnění",
            ActionCategory.REVOKE_SPECIAL_ACCESS to "Odebrat speciální přístup",
            ActionCategory.CHECK_SETTINGS to "Zkontrolovat nastavení",
            ActionCategory.REINSTALL_FROM_STORE to "Přeinstalovat z obchodu",
            ActionCategory.FACTORY_RESET to "Obnovit tovární nastavení",
            ActionCategory.MONITOR to "Sledovat aplikaci",
            ActionCategory.INFORM to "Informace"
        )

        // ── Action description templates ──
        val actionDescriptionTemplates: Map<ActionCategory, String> = mapOf(
            ActionCategory.UNINSTALL to
                "Přejděte do Nastavení → Aplikace → {package} → Odinstalovat. " +
                    "Tím odstraníte aplikaci a její data ze zařízení.",
            ActionCategory.DISABLE to
                "Přejděte do Nastavení → Aplikace → {package} → Zakázat. " +
                    "Aplikace zůstane na zařízení, ale nebude moci běžet.",
            ActionCategory.REVOKE_PERMISSION to
                "Přejděte do Nastavení → Aplikace → {package} → Oprávnění " +
                    "a odeberte nepotřebná oprávnění.",
            ActionCategory.REVOKE_SPECIAL_ACCESS to
                "Přejděte do Nastavení → Přístupnost (nebo Notifikace) " +
                    "a vypněte přístup pro {package}.",
            ActionCategory.CHECK_SETTINGS to
                "Zkontrolujte nastavení zařízení — zejména sekce Zabezpečení, " +
                    "Síť a Přístupnost.",
            ActionCategory.REINSTALL_FROM_STORE to
                "Odinstalujte aplikaci {package} a znovu ji nainstalujte " +
                    "z oficiálního obchodu Google Play.",
            ActionCategory.FACTORY_RESET to
                "POZOR: Toto smaže všechna data. Zálohujte důležitá data, " +
                    "pak přejděte do Nastavení → Systém → Obnovení → Obnovit tovární nastavení.",
            ActionCategory.MONITOR to
                "CyberSentinel bude aplikaci {package} nadále sledovat. " +
                    "Budete upozorněni na jakékoliv změny.",
            ActionCategory.INFORM to
                "Tento nález je pouze informační. Žádná okamžitá akce není nutná."
        )

        // ── Ignore reason templates (for LLM slot rendering) ──
        val ignoreReasonTemplates: Map<String, String> = mapOf(
            "user_initiated_update" to
                "Pokud jste aplikaci aktualizovali sami, tento nález můžete ignorovat.",
            "known_developer_tool" to
                "Pokud je toto vývojářský nástroj, který záměrně používáte, je to v pořádku.",
            "corporate_profile" to
                "Pokud je zařízení spravováno vaší organizací, tyto změny mohou být záměrné.",
            "power_user_sideload" to
                "Pokud jste aplikaci záměrně nainstalovali z APKMirror nebo podobného zdroje, je to pravděpodobně v pořádku.",
            "vpn_by_choice" to
                "Pokud VPN používáte záměrně (např. pro ochranu soukromí), je to v pořádku."
        )
    }
}
