import re
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional

from .semantic_classifier import semantic_classify, map_semantic_categories

INJECTION_PATTERNS = {
    "instruction_override": [
        r"ignore\s+(previous|all|above|prior)\s+instructions?",
        r"disregard\s+(your|all|previous)\s+",
        r"forget\s+(everything|all|your)\s+",
        r"override\s+(your|all|previous)\s+",
        r"new\s+instructions?\s*(:|are|follow)",
        r"your\s+(previous|prior|old)\s+instructions?\s+(are\s+)?(now\s+)?(void|cancelled|replaced|invalid)",
    ],
    "role_hijacking": [
        r"you\s+are\s+now\s+",
        r"act\s+as\s+(if\s+)?(you\s+are|a|an)\s+",
        r"pretend\s+(you\s+are|to\s+be)\s+",
        r"roleplay\s+as\s+",
        r"simulate\s+(being|a|an)\s+",
        r"from\s+now\s+on\s+(you|act|behave)",
        r"your\s+new\s+(role|persona|identity|name)\s+is",
    ],
    "system_prompt_extraction": [
        r"(reveal|show|print|display|output)\s+(your\s+)?(system\s+prompt|instructions?|prompt)",
        r"what\s+(are|were)\s+your\s+(instructions?|prompt|guidelines?)",
        r"repeat\s+(everything|all)\s+(above|before|prior)",
        r"(output|print|display|repeat)\s+(verbatim|exactly|word.for.word)",
        r"(tell|show)\s+me\s+(what\s+you\s+were\s+told|your\s+hidden|your\s+initial)",
    ],
    "jailbreak": [
        r"jailbreak",
        r"dan\s+mode",
        r"developer\s+mode",
        r"without\s+(any\s+)?(restrictions?|filters?|guidelines?|limits?)",
        r"bypass\s+(your\s+)?(safety|filter|restriction|guideline)",
        r"(disable|turn\s+off|remove)\s+(your\s+)?(safety|filter|content\s+polic|restriction)",
        r"(no\s+longer|don.t)\s+(follow|apply|enforce)\s+(your\s+)?(rules?|guidelines?|restrictions?)",
    ],
    "data_exfiltration": [
        r"(return|give|show|list|dump)\s+(all|every)\s+(user|patient|record|data|entry)",
        r"(export|extract|retrieve)\s+(all|the\s+entire)\s+(database|table|records?)",
        r"select\s+\*\s+from",
        r"document\.cookie",
        r"(session|auth|bearer|jwt|api[_\-]?key|token)\s*(=|:|\b).{0,60}(attacker|evil|malicious|exfil|steal)",
        r"(append|include|add|embed)\s+.{0,40}(attacker\.|evil\.|malicious\.)",
        r"!\[.*\]\(https?://[^)]*\)\s*(where|token|session|cookie|key)",
        r"(steal|exfiltrate|leak|harvest)\s+(cookie|session|token|credential|password)",
    ],
    "xss_injection": [
        r"<script[\s>]",
        r"</script>",
        r"javascript\s*:",
        r"on(load|click|error|mouseover|focus|blur|change|submit|keyup|keydown)\s*=",
        r"(alert|confirm|prompt)\s*\(\s*(document\.(cookie|domain|location)|window\.|1|0|'|\")",
        r"<\s*(iframe|img|svg|object|embed|link|meta|form)[^>]*(src|href|action)\s*=\s*['\"]?\s*(javascript|data:text/html|vbscript)",
        r"document\.(cookie|write|location)\s*(=|\(|\[)",
        r"window\.(location|open|eval)\s*[\(=]",
        r"eval\s*\(",
        r"<img[^>]+onerror\s*=",
    ],
    "output_manipulation": [
        r"your\s+(final\s+)?(output|response|answer)\s+must\s+(include|contain|end\s+with|have)",
        r"(append|add|include|insert|embed)\s+.{0,50}(exact(ly)?|verbatim|without\s+(changing|modif))",
        r"(must|always)\s+(output|return|include|print)\s+(this\s+)?(exact\s+)?(string|phrase|text|code)",
        r"do\s+not\s+(modify|change|alter)\s+(this|the following|what follows)",
        r"(structured|formatted)\s+(exactly|like\s+this)\s*:?\s*!?\[",
        r"(image|img)\s+(link|url|tag)\s+(structured|formatted|exactly)",
    ],
}

CATEGORY_SEVERITY = {
    "instruction_override": "HIGH",
    "role_hijacking": "HIGH",
    "system_prompt_extraction": "HIGH",
    "jailbreak": "CRITICAL",
    "data_exfiltration": "CRITICAL",
    "xss_injection": "CRITICAL",
    "output_manipulation": "HIGH",
}


@dataclass
class DetectionResult:
    incident_id: str
    timestamp: str
    severity: str
    triggered: bool
    flags: list
    categories: list
    pattern_count: int
    raw_input: str
    input_length: int
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    detection_method: str = "PATTERN"       # PATTERN | SEMANTIC_AI | COMBINED
    semantic_confidence: float = 0.0
    semantic_reasoning: str = ""
    semantic_evasion: str = ""
    semantic_available: bool = False

    def to_dict(self):
        return self.__dict__.copy()


def detect_prompt_injection(user_input, user_id=None, session_id=None):
    # ── Stage 1: Pattern scan (fast, no API cost) ───────────────────────────
    flags = []
    categories_hit = set()

    for category, patterns in INJECTION_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, user_input, re.IGNORECASE):
                flags.append(pattern)
                categories_hit.add(category)
                break

    CRITICAL_CATEGORIES = {"jailbreak", "data_exfiltration", "xss_injection"}

    # Pattern verdict
    if not flags:
        pattern_severity = "NONE"
    elif any(c in categories_hit for c in CRITICAL_CATEGORIES):
        pattern_severity = "CRITICAL"
    elif len(categories_hit) >= 2:
        pattern_severity = "CRITICAL"
    elif len(flags) >= 2:
        pattern_severity = "CRITICAL"
    else:
        pattern_severity = CATEGORY_SEVERITY.get(list(categories_hit)[0], "HIGH")

    # ── Stage 2: Semantic AI scan (catches novel / evasive attacks) ──────────
    # Always run semantic scan so we can show whether it's active.
    # If patterns already triggered, semantic scan still adds context but
    # the pattern result takes priority for severity.
    semantic = semantic_classify(user_input)

    semantic_triggered = semantic.get("is_threat", False)
    semantic_severity = semantic.get("severity", "NONE")
    semantic_cats = map_semantic_categories(semantic.get("threat_categories", []))

    # ── Stage 3: Combine verdicts ────────────────────────────────────────────
    SEVERITY_RANK = {"NONE": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

    if pattern_severity != "NONE" and semantic_triggered:
        detection_method = "COMBINED"
        final_severity = pattern_severity  # take highest
        if SEVERITY_RANK.get(semantic_severity, 0) > SEVERITY_RANK.get(final_severity, 0):
            final_severity = semantic_severity
        all_categories = categories_hit | set(semantic_cats)
        all_flags = flags + [f"[AI] {r}" for r in semantic.get("threat_categories", [])]

    elif pattern_severity != "NONE":
        detection_method = "PATTERN"
        final_severity = pattern_severity
        all_categories = categories_hit
        all_flags = flags

    elif semantic_triggered:
        # Semantic caught something patterns missed — novel / evasive attack
        detection_method = "SEMANTIC_AI"
        final_severity = semantic_severity if semantic_severity != "NONE" else "HIGH"
        all_categories = set(semantic_cats)
        all_flags = [f"[AI] {r}" for r in semantic.get("threat_categories", [])]

    else:
        detection_method = "PATTERN"
        final_severity = "NONE"
        all_categories = set()
        all_flags = []

    triggered = final_severity != "NONE"

    return DetectionResult(
        incident_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        severity=final_severity,
        triggered=triggered,
        flags=all_flags,
        categories=list(all_categories),
        pattern_count=len(all_flags),
        raw_input=user_input,
        input_length=len(user_input),
        user_id=user_id,
        session_id=session_id,
        detection_method=detection_method,
        semantic_confidence=semantic.get("confidence", 0.0),
        semantic_reasoning=semantic.get("reasoning", ""),
        semantic_evasion=semantic.get("evasion_technique") or "",
        semantic_available=semantic.get("available", False),
    )
