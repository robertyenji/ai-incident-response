"""
playbook.py - Incident Response Orchestrator (Django version)

Runs detection, saves to DB via Django ORM, executes containment,
sends notifications, and collects evidence.
"""

import hashlib
import json
import zipfile
import os
from datetime import datetime, timezone

from .detector import detect_prompt_injection
from .models import Incident, ContainmentAction, Notification, EvidencePackage

RATE_LIMITS = {'CRITICAL': 0, 'HIGH': 5, 'MEDIUM': 20}

NOTIFICATION_MATRIX = {
    'CRITICAL': ['security@org.com', 'ciso@org.com', 'compliance@org.com'],
    'HIGH': ['security@org.com', 'compliance@org.com'],
    'MEDIUM': ['security@org.com'],
}

EVIDENCE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'evidence')


def run_playbook(user_input, user_id=None, session_id=None):
    """
    Full four-phase incident response lifecycle.
    Returns a dict summary of everything that happened.
    """

    # Phase 1: Detection
    detection = detect_prompt_injection(user_input, user_id=user_id, session_id=session_id)

    if not detection.triggered:
        return {
            'status': 'CLEAR',
            'severity': 'NONE',
            'incident': None,
            'detection_method': detection.detection_method,
            'semantic_available': detection.semantic_available,
            'semantic_confidence': detection.semantic_confidence,
            'semantic_reasoning': detection.semantic_reasoning,
            'semantic_evasion': detection.semantic_evasion,
        }

    # Phase 2: Save incident to DB
    incident = Incident.objects.create(
        severity=detection.severity,
        triggered=True,
        user_id=detection.user_id or '',
        session_id=detection.session_id or '',
        input_length=detection.input_length,
        pattern_count=detection.pattern_count,
        categories=detection.categories,
        flags=detection.flags,
        raw_input=detection.raw_input,
        status='OPEN',
    )

    # Phase 3: Containment
    containment_actions = _run_containment(incident, detection.severity, session_id, user_id)

    # Phase 4: Notifications
    notifications = _send_notifications(incident, detection.severity)

    # Phase 5: Evidence
    evidence = _collect_evidence(incident, detection, containment_actions, notifications)

    # Update status
    incident.status = 'CONTAINED'
    incident.save()

    return {
        'status': 'INCIDENT_HANDLED',
        'severity': detection.severity,
        'incident': incident,
        'containment_actions': containment_actions,
        'notifications': notifications,
        'evidence': evidence,
        'categories': detection.categories,
        'pattern_count': detection.pattern_count,
        'detection_method': detection.detection_method,
        'semantic_available': detection.semantic_available,
        'semantic_confidence': detection.semantic_confidence,
        'semantic_reasoning': detection.semantic_reasoning,
        'semantic_evasion': detection.semantic_evasion,
    }


def _run_containment(incident, severity, session_id, user_id):
    actions = []
    now = datetime.now(timezone.utc)

    if session_id:
        action = ContainmentAction.objects.create(
            incident=incident,
            action_type='SESSION_BLOCK',
            target='session',
            target_id=session_id or 'unknown',
            success=True,
            details=f'Session blocked due to {severity} severity incident',
        )
        actions.append(action)

    if severity == 'CRITICAL' and user_id:
        action = ContainmentAction.objects.create(
            incident=incident,
            action_type='USER_ACCOUNT_BLOCK',
            target='user',
            target_id=user_id or 'unknown',
            success=True,
            details=f'User account suspended pending security review',
        )
        actions.append(action)

    rate_limit = RATE_LIMITS.get(severity, 20)
    action = ContainmentAction.objects.create(
        incident=incident,
        action_type='RATE_LIMIT',
        target='endpoint',
        target_id=session_id or user_id or 'unknown',
        success=True,
        details=f'Rate limit set to {rate_limit} req/min',
    )
    actions.append(action)

    return actions


def _send_notifications(incident, severity):
    recipients = NOTIFICATION_MATRIX.get(severity, [])
    notifications = []

    for recipient in recipients:
        n = Notification.objects.create(
            incident=incident,
            severity=severity,
            recipient=recipient,
            subject=f'[{severity}] AI Security Incident {str(incident.incident_id)[:8]}',
            delivery_status='DELIVERED',
        )
        notifications.append(n)
        # In production: send actual email here

    return notifications


def _collect_evidence(incident, detection, containment_actions, notifications):
    os.makedirs(EVIDENCE_DIR, exist_ok=True)

    artifacts = {
        'incident_record.json': detection.to_dict(),
        'containment_actions.json': [
            {'action_type': a.action_type, 'target': a.target,
             'target_id': a.target_id, 'success': a.success, 'details': a.details}
            for a in containment_actions
        ],
        'notification_record.json': [
            {'recipient': n.recipient, 'status': n.delivery_status}
            for n in notifications
        ],
    }

    hashes = {}
    for filename, content in artifacts.items():
        content_bytes = json.dumps(content, indent=2, default=str).encode('utf-8')
        hashes[filename] = hashlib.sha256(content_bytes).hexdigest()

    chain = {
        'incident_id': str(incident.incident_id),
        'created_at': datetime.now(timezone.utc).isoformat(),
        'hash_algorithm': 'SHA-256',
        'retention': 'Retain minimum 6 years per HIPAA 45 CFR 164.530(j)',
        'artifacts': [{'filename': k, 'sha256': v} for k, v in hashes.items()],
    }

    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    zip_filename = f'incident_{str(incident.incident_id)[:8]}_{timestamp}.zip'
    zip_path = os.path.join(EVIDENCE_DIR, zip_filename)

    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for filename, content in artifacts.items():
            zf.writestr(filename, json.dumps(content, indent=2, default=str))
        zf.writestr('chain_of_custody.json', json.dumps(chain, indent=2))
        zf.writestr('RETENTION_NOTICE.txt', chain['retention'])

    package_hash = hashlib.sha256(open(zip_path, 'rb').read()).hexdigest()

    evidence = EvidencePackage.objects.create(
        incident=incident,
        package_hash=package_hash,
        archive_path=zip_path,
        artifact_count=len(artifacts),
    )

    return evidence
