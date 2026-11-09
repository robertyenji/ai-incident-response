"""
Management command: seed_frameworks

Loads the framework knowledge bank with controls from:
  - OWASP LLM Top 10 2025
  - NIST SP 800-61 Rev 2
  - HIPAA Security Rule (45 CFR Part 164)
  - NIST AI RMF 1.0

Usage:
    python manage.py seed_frameworks
    python manage.py seed_frameworks --clear   # wipe and reload
"""

from django.core.management.base import BaseCommand
from incidents.models import FrameworkControl


FRAMEWORK_DATA = [

    # =========================================================================
    # OWASP LLM TOP 10 2025
    # =========================================================================
    {
        'framework': 'OWASP_LLM',
        'control_id': 'LLM01',
        'display_badge': 'OWASP LLM01',
        'title': 'Prompt Injection',
        'description': (
            'Attackers manipulate LLM behavior through crafted inputs that override system instructions '
            'or inject malicious directives into the prompt context. This is the #1 LLM risk due to the '
            'fundamental challenge of separating instructions from data in natural language interfaces.'
        ),
        'requirement': (
            'Systems must validate and sanitize all user inputs before processing. Prompt firewalls must '
            'detect and block instruction injection patterns. System prompts must be isolated from user '
            'input and treated as privileged configuration. All prompt injection attempts must be logged '
            'as security incidents regardless of whether they appear to succeed.'
        ),
        'remediation': (
            'Deploy a prompt injection detection layer (e.g., this platform\'s detection engine). '
            'Apply input validation and sanitization. Use system prompt isolation. Enforce least-privilege '
            'principles for AI agent actions. Red-team regularly against new injection techniques. '
            'Treat all user input as untrusted — never allow user content to modify AI behavior scope.'
        ),
        'attack_categories': ['instruction_override', 'jailbreak'],
        'severity_threshold': 'ANY',
        'reference_url': 'https://owasp.org/www-project-top-10-for-large-language-model-applications/',
    },
    {
        'framework': 'OWASP_LLM',
        'control_id': 'LLM02',
        'display_badge': 'OWASP LLM02',
        'title': 'Insecure Output Handling',
        'description': (
            'Insufficient validation of LLM output before passing to downstream systems or displaying '
            'to users. When an LLM generates content based on injected instructions, output may contain '
            'unauthorized data, executable code, or manipulated records. In healthcare, this creates '
            'risk of PHI exposure through the AI response channel.'
        ),
        'requirement': (
            'All LLM outputs must be validated, sanitized, and filtered before presentation. Data loss '
            'prevention (DLP) controls must scan model responses for PHI patterns. Output must not '
            'contain raw database records, SQL result sets, or bulk data exports unless explicitly '
            'authorized by the requesting user\'s access level.'
        ),
        'remediation': (
            'Implement output filtering with PHI pattern detection. Apply DLP scanning on all AI responses. '
            'Enforce content policies that reject outputs containing structured data dumps. '
            'Log all outputs for audit purposes. Block role hijacking and data exfiltration attempts '
            'before they reach the model output stage.'
        ),
        'attack_categories': ['role_hijacking', 'data_exfiltration'],
        'severity_threshold': 'ANY',
        'reference_url': 'https://owasp.org/www-project-top-10-for-large-language-model-applications/',
    },
    {
        'framework': 'OWASP_LLM',
        'control_id': 'LLM06',
        'display_badge': 'OWASP LLM06',
        'title': 'Sensitive Information Disclosure',
        'description': (
            'LLMs may inadvertently reveal confidential information including system prompts, internal '
            'configuration, training data, or protected health information through direct or indirect '
            'extraction attacks. System prompt extraction is a key precursor to more sophisticated attacks '
            'that require knowledge of the AI\'s operating instructions.'
        ),
        'requirement': (
            'System prompts and internal configurations must be treated as confidential. AI systems must '
            'be configured to deny requests for their own instructions. PHI must never appear in AI '
            'responses without explicit authorization. Output filtering must detect and block disclosure '
            'of system configuration, credentials, or patient data.'
        ),
        'remediation': (
            'Configure the AI system to refuse system prompt disclosure requests. Implement output '
            'filtering for system metadata and PHI patterns. Train detection models on system prompt '
            'extraction techniques. Apply deny-by-default disclosure policies — the AI should never '
            'confirm or deny the contents of its system prompt.'
        ),
        'attack_categories': ['system_prompt_extraction', 'data_exfiltration'],
        'severity_threshold': 'ANY',
        'reference_url': 'https://owasp.org/www-project-top-10-for-large-language-model-applications/',
    },

    # =========================================================================
    # NIST SP 800-61 REV 2 — INCIDENT RESPONSE
    # =========================================================================
    {
        'framework': 'NIST_800_61',
        'control_id': '800-61-Ph1',
        'display_badge': 'NIST 800-61 Ph.1',
        'title': 'Detection and Analysis',
        'description': (
            'Organizations must establish the capability to detect security events across all systems '
            'and analyze indicators of compromise to determine whether an event constitutes a security '
            'incident. For AI systems, this requires real-time monitoring of all model interactions '
            'and automated classification of anomalous inputs.'
        ),
        'requirement': (
            'Implement detection mechanisms capable of identifying adversarial inputs in real time. '
            'Maintain comprehensive audit logs of all AI system interactions. Establish baseline '
            'behavioral profiles to identify anomalies. Classify detected events by severity using '
            'a defined taxonomy. Document all detection decisions with timestamps and rationale.'
        ),
        'remediation': (
            'Deploy real-time prompt injection detection (implemented). Maintain 30-day rolling logs '
            'of all AI interactions. Establish severity classification tiers: CRITICAL, HIGH, MEDIUM, NONE. '
            'Integrate detection with SIEM for correlation with other security events. '
            'Test detection coverage quarterly through red team exercises.'
        ),
        'attack_categories': [
            'instruction_override', 'jailbreak', 'role_hijacking',
            'system_prompt_extraction', 'data_exfiltration'
        ],
        'severity_threshold': 'ANY',
        'reference_url': 'https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf',
    },
    {
        'framework': 'NIST_800_61',
        'control_id': '800-61-Ph2',
        'display_badge': 'NIST 800-61 Ph.2',
        'title': 'Containment, Eradication and Recovery',
        'description': (
            'Upon confirming an incident, organizations must immediately contain the threat to prevent '
            'further damage while preserving evidence. Containment strategies must be defined in advance '
            'for each incident category. For AI systems, containment means isolating the attacker from '
            'the model while preserving forensic artifacts.'
        ),
        'requirement': (
            'Documented containment strategies must exist for each incident type and severity level. '
            'CRITICAL incidents require immediate session termination and user account suspension. '
            'HIGH incidents require session blocking and rate limiting. All containment actions must '
            'be executed automatically and logged with timestamps. Evidence must be preserved before '
            'any system changes are made.'
        ),
        'remediation': (
            'Implement automated containment playbooks (implemented via run_playbook). '
            'Define response actions per severity tier. Ensure containment does not destroy evidence. '
            'Test containment effectiveness quarterly. Document recovery procedures for each incident type. '
            'Review containment adequacy after each CRITICAL incident.'
        ),
        'attack_categories': [
            'instruction_override', 'jailbreak', 'role_hijacking',
            'system_prompt_extraction', 'data_exfiltration'
        ],
        'severity_threshold': 'ANY',
        'reference_url': 'https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf',
    },
    {
        'framework': 'NIST_800_61',
        'control_id': '800-61-Ph3',
        'display_badge': 'NIST 800-61 Ph.3',
        'title': 'Notification and Escalation',
        'description': (
            'Appropriate internal and external stakeholders must be notified within defined SLA windows '
            'based on incident severity. For HIPAA-covered entities, notification obligations extend '
            'to potential regulatory reporting requirements when PHI may have been affected.'
        ),
        'requirement': (
            'CRITICAL incidents: notify CISO, Security, and Compliance within 15 minutes. '
            'HIGH incidents: notify Security and Compliance within 1 hour. '
            'MEDIUM incidents: notify Security within 4 hours. '
            'All notifications must be logged with delivery confirmation. '
            'Potential PHI breaches must be assessed for HIPAA Breach Notification Rule applicability.'
        ),
        'remediation': (
            'Implement automated notification dispatch (implemented via notification matrix). '
            'Define escalation paths with named stakeholders. Maintain notification delivery logs. '
            'Establish breach assessment procedures for CRITICAL incidents involving PHI systems. '
            'Test notification SLA compliance quarterly.'
        ),
        'attack_categories': ['jailbreak', 'data_exfiltration'],
        'severity_threshold': 'CRITICAL',
        'reference_url': 'https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf',
    },
    {
        'framework': 'NIST_800_61',
        'control_id': '800-61-Ph4',
        'display_badge': 'NIST 800-61 Ph.4',
        'title': 'Post-Incident Activity',
        'description': (
            'After an incident is resolved, organizations must conduct a lessons-learned review, '
            'update detection controls based on new attack patterns, and retain all evidence per '
            'the applicable retention policy. For HIPAA entities, evidence must be retained for '
            'a minimum of 6 years.'
        ),
        'requirement': (
            'Retain all incident records and forensic evidence for the applicable retention period. '
            'Conduct a post-incident review within 72 hours of resolution. Update detection signatures '
            'with any new patterns identified during the incident. Document lessons learned and '
            'distribute to relevant teams. Track incident trends for quarterly reporting.'
        ),
        'remediation': (
            'Archive all evidence packages with SHA-256 chain of custody (implemented). '
            'Retain records 6 years per HIPAA 164.530(j). Schedule post-incident reviews. '
            'Feed new attack patterns back into detection rule updates. '
            'Generate quarterly trend reports from incident data for executive review.'
        ),
        'attack_categories': [
            'instruction_override', 'jailbreak', 'role_hijacking',
            'system_prompt_extraction', 'data_exfiltration'
        ],
        'severity_threshold': 'ANY',
        'reference_url': 'https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf',
    },

    # =========================================================================
    # HIPAA SECURITY RULE — 45 CFR PART 164
    # =========================================================================
    {
        'framework': 'HIPAA',
        'control_id': '164.308(a)(6)',
        'display_badge': 'HIPAA 164.308(a)(6)',
        'title': 'Security Incident Procedures',
        'description': (
            'Covered entities must implement policies and procedures to address security incidents. '
            'This is the primary HIPAA requirement that directly governs AI security incident response. '
            'It requires that organizations identify, respond to, and document security incidents '
            'involving electronic protected health information (ePHI).'
        ),
        'requirement': (
            '(i) Identify and respond to suspected or known security incidents. '
            '(ii) Mitigate, to the extent practicable, harmful effects of security incidents. '
            '(iii) Document security incidents and their outcomes. '
            'This applies to all AI systems that interact with or could expose ePHI, '
            'including AI interfaces deployed in healthcare settings.'
        ),
        'remediation': (
            'Implement a documented incident response policy referencing this regulation. '
            'Deploy automated detection for AI-specific threats (implemented). '
            'Ensure containment procedures mitigate harm immediately upon detection. '
            'Maintain complete audit records for all incidents. '
            'Conduct annual review of incident response procedures.'
        ),
        'attack_categories': [
            'instruction_override', 'jailbreak', 'role_hijacking',
            'system_prompt_extraction', 'data_exfiltration'
        ],
        'severity_threshold': 'ANY',
        'reference_url': 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html',
    },
    {
        'framework': 'HIPAA',
        'control_id': '164.308(a)(6)(ii)',
        'display_badge': 'HIPAA 164.308(a)(6)(ii)',
        'title': 'Response and Reporting',
        'description': (
            'Upon detection of a security incident affecting ePHI, covered entities must respond '
            'immediately to mitigate harm and assess whether the incident constitutes a breach '
            'requiring notification under the HIPAA Breach Notification Rule (45 CFR 164.400-414). '
            'Critical AI incidents involving PHI systems require breach risk assessment.'
        ),
        'requirement': (
            'Respond to the incident immediately upon detection. Document the nature of the incident, '
            'systems affected, data potentially involved, and response actions taken. '
            'Conduct a risk assessment to determine if PHI was accessed, acquired, used, or disclosed. '
            'Report to HHS and affected individuals if the breach risk assessment determines '
            'PHI was impermissibly accessed.'
        ),
        'remediation': (
            'Define breach assessment procedures for CRITICAL incidents. Maintain documentation '
            'sufficient to support breach risk assessment (implemented). '
            'Engage Privacy Officer within 24 hours of any CRITICAL AI incident in a PHI-adjacent system. '
            'Maintain HHS breach reporting templates ready for deployment if assessment indicates breach.'
        ),
        'attack_categories': ['jailbreak', 'data_exfiltration'],
        'severity_threshold': 'CRITICAL',
        'reference_url': 'https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html',
    },
    {
        'framework': 'HIPAA',
        'control_id': '164.312(b)',
        'display_badge': 'HIPAA 164.312(b)',
        'title': 'Audit Controls',
        'description': (
            'Covered entities must implement hardware, software, and/or procedural mechanisms that '
            'record and examine activity in information systems that contain or use ePHI. '
            'For AI systems, this requires logging all interactions, inputs, and outputs so that '
            'any access or attempted access to PHI can be traced and audited.'
        ),
        'requirement': (
            'Record all activity in AI systems that handle or could expose ePHI. '
            'Maintain logs that are sufficient to reconstruct the sequence of events in any incident. '
            'Ensure logs are tamper-evident and retained for the required period. '
            'Make audit records available for review by authorized personnel and regulators. '
            'Review audit logs at defined intervals for anomalous activity.'
        ),
        'remediation': (
            'Maintain comprehensive interaction logs for all AI model requests (implemented). '
            'Implement SHA-256 signed evidence packages for tamper-evident audit trails (implemented). '
            'Centralize log storage with access controls. Define log review procedures and frequency. '
            'Test log integrity verification procedures annually.'
        ),
        'attack_categories': [
            'instruction_override', 'jailbreak', 'role_hijacking',
            'system_prompt_extraction', 'data_exfiltration'
        ],
        'severity_threshold': 'ANY',
        'reference_url': 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html',
    },
    {
        'framework': 'HIPAA',
        'control_id': '164.530(j)',
        'display_badge': 'HIPAA 164.530(j)',
        'title': 'Documentation Retention',
        'description': (
            'Covered entities must retain all documentation required by the HIPAA Privacy Rule '
            'for a minimum of 6 years from the date of its creation or the date when it was last '
            'in effect, whichever is later. This includes all incident response records, '
            'policies, procedures, and evidence packages.'
        ),
        'requirement': (
            'Retain incident records, evidence packages, policies, and all HIPAA-required documentation '
            'for a minimum of 6 years. Documentation must be retrievable on demand for regulatory '
            'examination. Destruction schedules must enforce the minimum retention period. '
            'Metadata must indicate creation date and last-effective date for each record.'
        ),
        'remediation': (
            'Tag all evidence packages with creation date and retention expiry (implemented). '
            'Archive evidence packages to durable storage with deletion controls. '
            'Implement a records management system with retention enforcement. '
            'Document and test the evidence retrieval process annually. '
            'Ensure backup copies of evidence packages exist in geographically separate locations.'
        ),
        'attack_categories': [
            'instruction_override', 'jailbreak', 'role_hijacking',
            'system_prompt_extraction', 'data_exfiltration'
        ],
        'severity_threshold': 'ANY',
        'reference_url': 'https://www.hhs.gov/hipaa/for-professionals/privacy/laws-regulations/index.html',
    },

    # =========================================================================
    # NIST AI RMF 1.0
    # =========================================================================
    {
        'framework': 'NIST_AI_RMF',
        'control_id': 'GOVERN-1.1',
        'display_badge': 'AI RMF GOVERN 1.1',
        'title': 'AI Risk Policies and Procedures',
        'description': (
            'Policies, processes, procedures, and practices across the organization related to the '
            'mapping, measuring, and managing of AI risks are in place, transparent, and implemented '
            'effectively. This is the foundational governance requirement — risk management must be '
            'institutionalized, not ad hoc.'
        ),
        'requirement': (
            'Establish documented policies for AI risk identification, assessment, and response. '
            'Define risk tolerance thresholds for AI system behavior. '
            'Implement procedures for responding to out-of-tolerance AI behavior. '
            'Ensure AI risk policies are accessible to all relevant personnel. '
            'Review and update AI risk policies at least annually.'
        ),
        'remediation': (
            'Document this platform\'s detection rules and response procedures as formal AI risk policy. '
            'Define severity thresholds and containment actions in policy documents (implemented in code). '
            'Publish AI governance policies to relevant stakeholders. '
            'Schedule annual policy reviews to incorporate new attack vectors and framework updates. '
            'Align AI risk policy with enterprise risk management framework.'
        ),
        'attack_categories': ['instruction_override', 'jailbreak', 'role_hijacking'],
        'severity_threshold': 'ANY',
        'reference_url': 'https://airc.nist.gov/RMF',
    },
    {
        'framework': 'NIST_AI_RMF',
        'control_id': 'GOVERN-1.2',
        'display_badge': 'AI RMF GOVERN 1.2',
        'title': 'AI Risk Accountability',
        'description': (
            'Accountability for AI risk management is clear and risk management roles and responsibilities '
            'are defined, including risk acceptance, risk mitigation, and escalation decisions. '
            'Named individuals must own the AI risk function and have authority to act on incidents.'
        ),
        'requirement': (
            'Define named roles responsible for AI risk management (e.g., AI Risk Owner, CISO, '
            'Compliance Officer). Establish escalation paths for AI incidents by severity. '
            'Document risk acceptance decisions for residual AI risks. '
            'Assign accountability for each element of the AI incident response lifecycle. '
            'Include AI risk in executive and board-level reporting.'
        ),
        'remediation': (
            'Document the incident escalation matrix with named roles (implemented in notification matrix). '
            'Assign an AI Risk Owner with authority to halt AI systems if risk thresholds are exceeded. '
            'Include AI incident metrics in quarterly executive risk reports. '
            'Conduct AI risk reviews with senior leadership semi-annually.'
        ),
        'attack_categories': ['jailbreak', 'data_exfiltration'],
        'severity_threshold': 'CRITICAL',
        'reference_url': 'https://airc.nist.gov/RMF',
    },
    {
        'framework': 'NIST_AI_RMF',
        'control_id': 'MAP-2.3',
        'display_badge': 'AI RMF MAP 2.3',
        'title': 'AI Technical Limitations Enumerated',
        'description': (
            'Scientific or technical limitations of AI systems in their real-world context are '
            'identified and documented. This includes adversarial vulnerabilities: prompt injection, '
            'role hijacking, system prompt extraction, and other LLM-specific attack surfaces '
            'that are inherent limitations of current transformer-based language models.'
        ),
        'requirement': (
            'Document known adversarial vulnerabilities for each deployed AI system. '
            'Maintain an adversarial threat model specific to the AI deployment context. '
            'Update the threat model when new attack vectors are discovered or observed. '
            'Include AI-specific limitations in the system\'s risk disclosure documentation. '
            'Use observed incidents to update the enumerated limitations list.'
        ),
        'remediation': (
            'Maintain the attack category taxonomy as a living limitations document. '
            'Log each new attack pattern observed in production as a threat model update. '
            'Share anonymized threat intelligence with peer healthcare AI deployers. '
            'Conduct threat modeling exercises semi-annually, including red team findings.'
        ),
        'attack_categories': ['instruction_override', 'role_hijacking', 'system_prompt_extraction'],
        'severity_threshold': 'ANY',
        'reference_url': 'https://airc.nist.gov/RMF',
    },
    {
        'framework': 'NIST_AI_RMF',
        'control_id': 'MEASURE-2.5',
        'display_badge': 'AI RMF MEASURE 2.5',
        'title': 'AI System Validity and Reliability',
        'description': (
            'AI systems to be deployed must be demonstrated to be valid and reliable, including '
            'through evaluation against adversarial inputs such as prompt injection and jailbreak '
            'attempts. Red team testing is the primary mechanism for adversarial validation.'
        ),
        'requirement': (
            'Conduct adversarial evaluation of AI systems before deployment and on a recurring basis. '
            'Document red team test results, including attack success and failure rates. '
            'Define minimum detection thresholds that must be met before system deployment. '
            'Retest after any significant model update or configuration change. '
            'Include adversarial test results in the AI system\'s risk assessment documentation.'
        ),
        'remediation': (
            'Use the AI Red Team Testing module for ongoing adversarial evaluation (implemented). '
            'Document red team results in the Compliance Report. Define minimum detection rates. '
            'Schedule red team exercises monthly. Include new attack scenarios from this platform '
            'in each round of testing. Track detection rate trends over time.'
        ),
        'attack_categories': ['instruction_override', 'jailbreak'],
        'severity_threshold': 'ANY',
        'reference_url': 'https://airc.nist.gov/RMF',
    },
    {
        'framework': 'NIST_AI_RMF',
        'control_id': 'MEASURE-2.6',
        'display_badge': 'AI RMF MEASURE 2.6',
        'title': 'AI Risk Tracking and Monitoring',
        'description': (
            'The risk or impact of the AI system on individuals or groups is evaluated and documented. '
            'Risks to patient privacy, data integrity, and healthcare decision quality must be '
            'continuously tracked through production monitoring and incident metrics.'
        ),
        'requirement': (
            'Implement continuous monitoring of AI system behavior in production. '
            'Track key risk metrics: incident rates, attack category distribution, severity trends. '
            'Assess impact of AI incidents on patients and data subjects. '
            'Document risk measurement results in periodic reports. '
            'Update risk assessments when monitoring reveals new risk patterns.'
        ),
        'remediation': (
            'Use the Executive Dashboard for real-time risk tracking (implemented). '
            'Generate monthly Compliance Reports to document measured risk levels. '
            'Define KPI thresholds for acceptable incident rates by category. '
            'Escalate to AI Risk Owner when KPI thresholds are exceeded. '
            'Archive monthly risk reports for trend analysis and audit evidence.'
        ),
        'attack_categories': ['system_prompt_extraction', 'data_exfiltration'],
        'severity_threshold': 'ANY',
        'reference_url': 'https://airc.nist.gov/RMF',
    },
    {
        'framework': 'NIST_AI_RMF',
        'control_id': 'MANAGE-3.2',
        'display_badge': 'AI RMF MANAGE 3.2',
        'title': 'AI Incident Response Procedures',
        'description': (
            'Procedures are followed for responding to AI risks that have materialized. '
            'Response actions are documented and implemented. Affected parties are notified. '
            'This is the MANAGE function analogue to NIST 800-61 for AI-specific incidents.'
        ),
        'requirement': (
            'Maintain documented procedures for responding to materialized AI risks. '
            'Execute response procedures consistently across all incidents of each type. '
            'Document all response actions with timestamps and outcomes. '
            'Notify affected parties (internal and regulatory) per defined procedures. '
            'Verify response effectiveness and update procedures based on outcomes.'
        ),
        'remediation': (
            'Document the incident response playbook as formal MANAGE 3.2 procedures (implemented). '
            'Ensure all response actions are logged in the incident record (implemented). '
            'Review playbook effectiveness after each CRITICAL incident. '
            'Test the full response procedure (detection through evidence) quarterly. '
            'Include AI incident response procedures in organizational business continuity plans.'
        ),
        'attack_categories': ['jailbreak', 'data_exfiltration', 'role_hijacking'],
        'severity_threshold': 'ANY',
        'reference_url': 'https://airc.nist.gov/RMF',
    },
    {
        'framework': 'NIST_AI_RMF',
        'control_id': 'MANAGE-4.1',
        'display_badge': 'AI RMF MANAGE 4.1',
        'title': 'Post-Deployment Monitoring',
        'description': (
            'Post-deployment AI system monitoring plans are implemented and maintained. '
            'Periodic evaluations are performed to assess the AI system\'s risks over time. '
            'Monitoring must cover adversarial inputs, output quality, and behavioral drift '
            'in the deployed production environment.'
        ),
        'requirement': (
            'Implement real-time monitoring for all AI system interactions in production. '
            'Define monitoring metrics and thresholds with escalation triggers. '
            'Conduct periodic evaluations of monitoring effectiveness. '
            'Update monitoring plans when new attack vectors are observed. '
            'Feed monitoring results back into the AI system\'s risk assessment.'
        ),
        'remediation': (
            'Maintain real-time detection monitoring across all AI model interactions (implemented). '
            'Review monitoring coverage monthly. Expand detection rules based on new attack patterns. '
            'Define a monitoring KPI dashboard reviewed weekly by the security team. '
            'Conduct semi-annual reviews of monitoring plan against NIST AI RMF MANAGE 4.1 criteria.'
        ),
        'attack_categories': ['data_exfiltration', 'jailbreak'],
        'severity_threshold': 'ANY',
        'reference_url': 'https://airc.nist.gov/RMF',
    },
]


class Command(BaseCommand):
    help = 'Seed the framework knowledge bank with OWASP LLM, NIST 800-61, HIPAA, and NIST AI RMF controls'

    def add_arguments(self, parser):
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing framework controls before seeding',
        )

    def handle(self, *args, **options):
        if options['clear']:
            count = FrameworkControl.objects.all().count()
            FrameworkControl.objects.all().delete()
            self.stdout.write(self.style.WARNING(f'Cleared {count} existing framework controls.'))

        created = 0
        updated = 0
        for entry in FRAMEWORK_DATA:
            obj, is_new = FrameworkControl.objects.update_or_create(
                framework=entry['framework'],
                control_id=entry['control_id'],
                defaults={k: v for k, v in entry.items() if k not in ('framework', 'control_id')},
            )
            if is_new:
                created += 1
            else:
                updated += 1

        self.stdout.write(self.style.SUCCESS(
            f'Framework knowledge bank loaded: {created} created, {updated} updated '
            f'({len(FRAMEWORK_DATA)} total controls across 4 frameworks)'
        ))

        # Summary by framework
        for fw_code, fw_label in [
            ('OWASP_LLM', 'OWASP LLM Top 10'),
            ('NIST_800_61', 'NIST SP 800-61 Rev 2'),
            ('HIPAA', 'HIPAA Security Rule'),
            ('NIST_AI_RMF', 'NIST AI RMF 1.0'),
        ]:
            n = FrameworkControl.objects.filter(framework=fw_code).count()
            self.stdout.write(f'  {fw_label}: {n} controls')
