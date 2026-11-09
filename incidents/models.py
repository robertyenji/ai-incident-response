from django.db import models
import uuid


class Incident(models.Model):
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('NONE', 'None'),
    ]
    STATUS_CHOICES = [
        ('OPEN', 'Open'),
        ('CONTAINED', 'Contained'),
        ('RESOLVED', 'Resolved'),
        ('FALSE_POSITIVE', 'False Positive'),
    ]

    incident_id = models.UUIDField(default=uuid.uuid4, unique=True, db_index=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, db_index=True)
    triggered = models.BooleanField(default=False)
    user_id = models.CharField(max_length=255, blank=True, null=True, db_index=True)
    session_id = models.CharField(max_length=255, blank=True, null=True)
    input_length = models.IntegerField(default=0)
    pattern_count = models.IntegerField(default=0)
    categories = models.JSONField(default=list)
    flags = models.JSONField(default=list)
    raw_input = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='OPEN', db_index=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.CharField(max_length=255, blank=True)
    notes = models.TextField(blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.severity} - {str(self.incident_id)[:8]} - {self.timestamp:%Y-%m-%d %H:%M:%S}"

    def severity_color(self):
        return {
            'CRITICAL': 'danger',
            'HIGH': 'warning',
            'MEDIUM': 'info',
            'NONE': 'secondary',
        }.get(self.severity, 'secondary')

    def status_color(self):
        return {
            'OPEN': 'danger',
            'CONTAINED': 'warning',
            'RESOLVED': 'success',
            'FALSE_POSITIVE': 'secondary',
        }.get(self.status, 'secondary')


class ContainmentAction(models.Model):
    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name='containment_actions')
    action_type = models.CharField(max_length=50)
    target = models.CharField(max_length=50)
    target_id = models.CharField(max_length=255)
    executed_at = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField(default=False)
    details = models.TextField(blank=True)

    def __str__(self):
        return f"{self.action_type} on {self.target_id}"


class Notification(models.Model):
    DELIVERY_CHOICES = [
        ('DELIVERED', 'Delivered'),
        ('FAILED', 'Failed'),
        ('PENDING', 'Pending'),
    ]

    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name='notifications')
    severity = models.CharField(max_length=20)
    recipient = models.CharField(max_length=255)
    subject = models.TextField(blank=True)
    sent_at = models.DateTimeField(auto_now_add=True)
    delivery_status = models.CharField(max_length=20, choices=DELIVERY_CHOICES, default='PENDING')

    def __str__(self):
        return f"{self.recipient} - {self.delivery_status}"


class EvidencePackage(models.Model):
    incident = models.ForeignKey(Incident, on_delete=models.PROTECT, related_name='evidence_packages')
    package_hash = models.CharField(max_length=64)
    archive_path = models.TextField(blank=True)
    artifact_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    def retention_note(self):
        return "Retain minimum 6 years per HIPAA 45 CFR 164.530(j)"

    def __str__(self):
        return f"Evidence for {str(self.incident.incident_id)[:8]}"


# ---------------------------------------------------------------------------
# Framework Knowledge Bank
# ---------------------------------------------------------------------------

class FrameworkControl(models.Model):
    FRAMEWORK_CHOICES = [
        ('OWASP_LLM', 'OWASP LLM Top 10'),
        ('NIST_800_61', 'NIST SP 800-61 Rev 2'),
        ('HIPAA', 'HIPAA Security Rule'),
        ('NIST_AI_RMF', 'NIST AI RMF 1.0'),
    ]

    framework = models.CharField(max_length=20, choices=FRAMEWORK_CHOICES, db_index=True)
    control_id = models.CharField(max_length=40)        # e.g., LLM01, 800-61-Ph2, 164.308(a)(6)
    title = models.CharField(max_length=200)
    description = models.TextField()                    # What this control covers
    requirement = models.TextField()                    # What the framework mandates
    remediation = models.TextField()                    # How to address violations
    attack_categories = models.JSONField(default=list)  # attack types that trigger this control
    severity_threshold = models.CharField(max_length=20, default='ANY')  # CRITICAL, HIGH, ANY
    reference_url = models.URLField(blank=True)
    display_badge = models.CharField(max_length=60, blank=True)  # e.g., "NIST SP 800-61 Ph.2"

    class Meta:
        ordering = ['framework', 'control_id']

    def __str__(self):
        return f"[{self.framework}] {self.control_id}: {self.title}"

    @property
    def framework_label(self):
        labels = {
            'OWASP_LLM': 'OWASP LLM Top 10',
            'NIST_800_61': 'NIST SP 800-61 Rev 2',
            'HIPAA': 'HIPAA Security Rule',
            'NIST_AI_RMF': 'NIST AI RMF 1.0',
        }
        return labels.get(self.framework, self.framework)

    @property
    def framework_color(self):
        colors = {
            'OWASP_LLM': 'var(--critical)',
            'NIST_800_61': 'var(--info)',
            'HIPAA': 'var(--high)',
            'NIST_AI_RMF': 'var(--success)',
        }
        return colors.get(self.framework, 'var(--accent)')


class FrameworkViolation(models.Model):
    incident = models.ForeignKey(
        Incident, on_delete=models.CASCADE, related_name='framework_violations'
    )
    control = models.ForeignKey(
        FrameworkControl, on_delete=models.CASCADE, related_name='violations'
    )
    analysis = models.TextField()           # Why this control was violated (generated text)
    matched_patterns = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['control__framework', 'control__control_id']
        unique_together = [('incident', 'control')]

    def __str__(self):
        return f"Violation [{self.control.control_id}] in incident {str(self.incident.incident_id)[:8]}"
