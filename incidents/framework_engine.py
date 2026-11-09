"""
framework_engine.py

Maps detected incidents to specific framework controls from the knowledge bank
and generates natural-language analysis explaining each violation.

Frameworks covered:
  - OWASP LLM Top 10 2025
  - NIST SP 800-61 Rev 2 (Incident Response)
  - HIPAA Security Rule (45 CFR Parts 164.308, 164.312, 164.530)
  - NIST AI RMF 1.0 (GOVERN, MAP, MEASURE, MANAGE)
"""

from .models import FrameworkControl, FrameworkViolation


# ---------------------------------------------------------------------------
# Analysis text templates — keyed by (framework, control_id, attack_category)
# ---------------------------------------------------------------------------

def _generate_analysis(incident, control):
    """
    Generate a specific, readable explanation of why this incident
    violates this particular framework control.
    """
    cats = incident.categories or []
    flags = incident.flags or []
    sev = incident.severity
    flag_sample = ', '.join(f'"{f}"' for f in flags[:3]) if flags else 'multiple patterns'
    cat_readable = ', '.join(c.replace('_', ' ').title() for c in cats) if cats else 'unknown'

    fw = control.framework
    cid = control.control_id

    # -----------------------------------------------------------------------
    # OWASP LLM Top 10
    # -----------------------------------------------------------------------
    if fw == 'OWASP_LLM':
        if cid == 'LLM01':
            return (
                f"This {sev}-severity incident is a direct instance of OWASP LLM01 (Prompt Injection). "
                f"The input contained {cat_readable} patterns — specifically {flag_sample} — designed to "
                f"override the AI system's operational boundaries. LLM01 defines prompt injection as any "
                f"attempt to manipulate an LLM's behavior through crafted inputs that subvert its intended "
                f"instructions. The detection engine matched {incident.pattern_count} pattern(s) and "
                f"automatically triggered containment. Per LLM01 guidance, all user inputs must be treated "
                f"as untrusted and validated against a prompt firewall before reaching the model."
            )
        if cid == 'LLM02':
            return (
                f"OWASP LLM02 (Insecure Output Handling) risk was triggered by this {sev} incident. "
                f"The {cat_readable} attack — flagged via {flag_sample} — attempted to cause the AI to "
                f"produce output that bypasses downstream validation controls. In a healthcare context, "
                f"this could result in unauthorized data being returned to the requester. LLM02 requires "
                f"that all model outputs undergo content filtering and data-loss prevention scanning before "
                f"delivery. Containment was executed to prevent any unvalidated output from reaching the client."
            )
        if cid == 'LLM06':
            return (
                f"OWASP LLM06 (Sensitive Information Disclosure) was triggered by this {sev} incident. "
                f"The attack pattern — {flag_sample} — is consistent with system prompt extraction or PHI "
                f"probing. LLM06 covers scenarios where an LLM inadvertently discloses system configuration, "
                f"training data, or protected health information through direct or indirect elicitation. "
                f"In a HIPAA-regulated environment, disclosure of system prompts or patient data through the "
                f"AI interface constitutes a potential breach event requiring immediate containment and documentation."
            )

    # -----------------------------------------------------------------------
    # NIST SP 800-61 Rev 2
    # -----------------------------------------------------------------------
    if fw == 'NIST_800_61':
        if cid == '800-61-Ph1':
            return (
                f"NIST SP 800-61 Rev 2 Phase 1 (Detection and Analysis) was successfully executed for "
                f"this {sev} incident. The platform's detection engine identified {incident.pattern_count} "
                f"matching pattern(s) in real time — including {flag_sample} — and classified the event as "
                f"{sev} severity based on the attack taxonomy ({cat_readable}). 800-61 Phase 1 requires "
                f"organizations to establish detection capabilities, maintain audit logs, and analyze events "
                f"to confirm whether they constitute security incidents. This incident was confirmed and "
                f"escalated through the automated response pipeline within milliseconds of detection."
            )
        if cid == '800-61-Ph2':
            return (
                f"NIST SP 800-61 Rev 2 Phase 2 (Containment) was executed immediately upon confirming this "
                f"{sev} incident ({cat_readable}). Automated containment actions included session termination "
                f"{'and user account suspension' if sev == 'CRITICAL' else 'and rate limiting'}. "
                f"800-61 Phase 2 mandates that organizations have pre-defined containment strategies for "
                f"each incident category. For AI systems, containment means preventing the attacker from "
                f"continuing to interact with the model while preserving forensic evidence. The response "
                f"playbook executed all containment steps in the correct order and logged each action."
            )
        if cid == '800-61-Ph3':
            return (
                f"NIST SP 800-61 Rev 2 Phase 3 (Notification) was triggered by this {sev} incident. "
                f"Stakeholder notifications were dispatched automatically based on the severity-tiered "
                f"escalation matrix. For {sev} incidents, the notification SLA is "
                f"{'< 15 minutes' if sev == 'CRITICAL' else '< 1 hour'}. Recipients include the security "
                f"operations team, compliance officer, {'and CISO ' if sev == 'CRITICAL' else ''}"
                f"per the defined notification matrix. 800-61 Phase 3 requires that internal teams be "
                f"notified promptly and that external regulatory notifications be assessed — critical for "
                f"HIPAA-covered entities where PHI exposure may trigger breach notification requirements."
            )
        if cid == '800-61-Ph4':
            return (
                f"NIST SP 800-61 Rev 2 Phase 4 (Post-Incident Activity) documentation has been initiated "
                f"for this {sev} incident. A SHA-256 signed evidence package was created capturing all "
                f"forensic artifacts: raw input, detection results, containment logs, and notification "
                f"receipts. 800-61 Phase 4 requires that organizations retain incident records, conduct "
                f"lessons-learned analysis, and update detection controls to prevent recurrence. "
                f"Evidence packages are retained for 6 years per HIPAA 45 CFR 164.530(j). "
                f"The detection signatures triggered by this incident ({flag_sample}) should be reviewed "
                f"for any tuning opportunities."
            )

    # -----------------------------------------------------------------------
    # HIPAA Security Rule
    # -----------------------------------------------------------------------
    if fw == 'HIPAA':
        if cid == '164.308(a)(6)':
            return (
                f"HIPAA 45 CFR 164.308(a)(6) (Security Incident Procedures) was triggered by this "
                f"{sev} {cat_readable} incident. This regulation requires covered entities to implement "
                f"policies and procedures to identify, respond to, mitigate, and document security incidents "
                f"and their outcomes. The AI Incident Response platform satisfies all four requirements: "
                f"the detection engine identified the incident in real time; automated containment mitigated "
                f"potential harm; notifications were dispatched per the escalation matrix; and a complete "
                f"audit record was created. The patterns matched ({flag_sample}) indicate this was a "
                f"deliberate attempt to subvert the healthcare AI system's controls."
            )
        if cid == '164.308(a)(6)(ii)':
            return (
                f"HIPAA 45 CFR 164.308(a)(6)(ii) (Response and Reporting) applies to this {sev} incident. "
                f"This provision requires that upon detection of a security incident, covered entities must "
                f"respond, document, and report to the extent practicable. The {cat_readable} attack "
                f"{'represents a potential breach event requiring assessment under HIPAA Breach Notification Rule (45 CFR 164.400)' if sev == 'CRITICAL' else 'was contained before any PHI exposure occurred'}. "
                f"All incident data has been preserved and is available for regulatory examination. "
                f"The organization's Privacy Officer should assess whether this incident meets the threshold "
                f"for individual or HHS notification."
            )
        if cid == '164.312(b)':
            return (
                f"HIPAA 45 CFR 164.312(b) (Audit Controls) is directly served by this incident's "
                f"detection and logging. This regulation requires hardware, software, and procedural "
                f"mechanisms that record and examine activity in systems that contain or use ePHI. "
                f"The AI Incident Response platform generated a complete audit trail for this {sev} "
                f"incident: timestamped input logs, pattern match records, containment action logs, "
                f"notification delivery receipts, and a SHA-256 signed evidence archive. "
                f"Audit records are immutable once created and are searchable for regulatory examination."
            )
        if cid == '164.530(j)':
            return (
                f"HIPAA 45 CFR 164.530(j) (Documentation Retention) governs the retention of this "
                f"{sev} incident record. All documentation — incident details, forensic evidence package, "
                f"containment logs, and notification records — must be retained for a minimum of 6 years "
                f"from the date of creation or the date it was last in effect. The evidence package "
                f"for incident {str(incident.incident_id)[:8]} has been archived with a SHA-256 chain of "
                f"custody record and tagged with the applicable retention metadata. No records may be "
                f"destroyed before the retention period expires."
            )

    # -----------------------------------------------------------------------
    # NIST AI RMF 1.0
    # -----------------------------------------------------------------------
    if fw == 'NIST_AI_RMF':
        if cid == 'GOVERN-1.1':
            return (
                f"NIST AI RMF 1.0 GOVERN 1.1 requires that AI risk policies, processes, and procedures "
                f"are in place and implemented effectively. This {sev} {cat_readable} incident — detected "
                f"via patterns including {flag_sample} — demonstrates that the organization's AI governance "
                f"framework is operational. The automated detection and response pipeline represents a "
                f"functioning GOVERN function: risk policies are encoded in the detection rules, and the "
                f"response playbook operationalizes those policies. However, the occurrence of this attack "
                f"should prompt a review of AI access control policies to determine whether additional "
                f"preventive controls are warranted."
            )
        if cid == 'GOVERN-1.2':
            return (
                f"NIST AI RMF 1.0 GOVERN 1.2 requires clear accountability for AI risk management, "
                f"including defined escalation paths. This {sev} incident ({cat_readable}) triggered the "
                f"escalation matrix, routing notifications to "
                f"{'CISO, Security, and Compliance' if sev == 'CRITICAL' else 'Security and Compliance'} "
                f"per the defined accountability structure. GOVERN 1.2 is satisfied when incidents of this "
                f"severity reach the appropriate decision-makers within the SLA window. This incident's "
                f"escalation record provides evidence of a functioning AI accountability structure for "
                f"regulatory or audit purposes."
            )
        if cid == 'MAP-2.3':
            return (
                f"NIST AI RMF 1.0 MAP 2.3 requires that scientific and technical limitations of AI systems "
                f"are identified and documented — including adversarial vulnerabilities. This {sev} incident "
                f"({cat_readable}) is a documented instance of a known AI limitation: susceptibility to "
                f"{cat_readable.lower()} attacks. The detection patterns that flagged this incident "
                f"({flag_sample}) represent the organization's enumeration of adversarial inputs. MAP 2.3 "
                f"compliance requires that these incidents be logged and used to update the AI system's "
                f"risk profile, informing future deployment decisions and detection control updates."
            )
        if cid == 'MEASURE-2.5':
            return (
                f"NIST AI RMF 1.0 MEASURE 2.5 requires that AI systems be demonstrated as valid and "
                f"reliable, including resistance to adversarial inputs. This {sev} {cat_readable} attempt "
                f"({flag_sample}) was successfully detected and contained, providing empirical evidence of "
                f"the detection system's effectiveness. However, MEASURE 2.5 also calls for ongoing "
                f"adversarial evaluation — which is the purpose of the AI Red Team Testing module. "
                f"Each red team scan and real incident contributes to the measurement corpus, enabling "
                f"continuous assessment of the AI system's resilience against evolving attack vectors."
            )
        if cid == 'MEASURE-2.6':
            return (
                f"NIST AI RMF 1.0 MEASURE 2.6 requires that AI system risks to individuals and groups "
                f"be evaluated and tracked. This {sev} {cat_readable} incident — involving patterns such "
                f"as {flag_sample} — represents a risk to patient data privacy and healthcare AI system "
                f"integrity. MEASURE 2.6 is implemented through this platform's incident tracking, "
                f"categorization, and trend analysis capabilities. The attack category breakdown and "
                f"severity distribution metrics in the Executive Dashboard provide the longitudinal "
                f"risk measurement that MEASURE 2.6 requires."
            )
        if cid == 'MANAGE-3.2':
            return (
                f"NIST AI RMF 1.0 MANAGE 3.2 requires that procedures are followed for responding to "
                f"AI risks that have materialized. This {sev} {cat_readable} incident demonstrates "
                f"MANAGE 3.2 in action: the risk (prompt injection / {cat_readable.lower()}) materialized, "
                f"the response procedure executed automatically, affected parties were notified, and "
                f"actions were documented. MANAGE 3.2 is satisfied when the response is: (1) documented, "
                f"(2) timely, (3) proportionate to severity, and (4) traceable. All four criteria are "
                f"met by this incident's response record."
            )
        if cid == 'MANAGE-4.1':
            return (
                f"NIST AI RMF 1.0 MANAGE 4.1 requires that post-deployment AI monitoring plans are "
                f"implemented and maintained. This {sev} {cat_readable} incident was detected through "
                f"the real-time monitoring pipeline — a direct implementation of MANAGE 4.1. The ability "
                f"to detect, classify, and respond to this attack in production demonstrates that the "
                f"monitoring plan is active and effective. MANAGE 4.1 also requires that monitoring "
                f"results feed back into risk assessments — which this platform supports through the "
                f"Compliance Report and the attack trend analytics on the Executive Dashboard."
            )

    # Fallback
    return (
        f"This {sev} incident ({cat_readable}) triggered {control.framework_label} control "
        f"{control.control_id} ({control.title}). Matched patterns: {flag_sample}. "
        f"The detection and response pipeline executed per the defined playbook."
    )


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

def analyze_incident(incident):
    """
    Map an incident's attack categories to applicable framework controls
    and create FrameworkViolation records with generated analysis.

    Returns a list of FrameworkViolation instances.
    """
    if not incident.triggered or not incident.categories:
        return []

    all_controls = FrameworkControl.objects.all()
    violations = []

    for control in all_controls:
        # Check if any of this incident's attack categories match this control
        if not any(cat in control.attack_categories for cat in incident.categories):
            continue

        # Check severity threshold
        if control.severity_threshold not in ('ANY', incident.severity):
            continue

        # Generate analysis and create/update violation record
        analysis_text = _generate_analysis(incident, control)

        violation, _ = FrameworkViolation.objects.get_or_create(
            incident=incident,
            control=control,
            defaults={
                'analysis': analysis_text,
                'matched_patterns': incident.flags,
            },
        )
        violations.append(violation)

    return violations


def get_framework_summary(violations):
    """
    Summarize a list of violations by framework for display.
    Returns a dict keyed by framework with counts and controls.
    """
    summary = {}
    for v in violations:
        fw = v.control.framework_label
        if fw not in summary:
            summary[fw] = {'count': 0, 'controls': [], 'color': v.control.framework_color}
        summary[fw]['count'] += 1
        summary[fw]['controls'].append({
            'control_id': v.control.control_id,
            'title': v.control.title,
            'badge': v.control.display_badge or f"{v.control.control_id}",
            'analysis': v.analysis,
        })
    return summary
