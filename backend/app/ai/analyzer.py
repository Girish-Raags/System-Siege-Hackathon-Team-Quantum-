"""
AI-driven security intelligence layer.

If ANTHROPIC_API_KEY is configured, uses Claude to read the detected change
(diff excerpt) and vulnerability findings for an asset, then produces a risk
score, human-readable summary, and prioritized remediation steps.

If no API key is set, falls back to transparent, deterministic rule-based
scoring so the platform is fully usable out of the box.
"""
import json
from typing import Optional

from app.config import settings

SEVERITY_WEIGHTS = {"critical": 40, "high": 25, "medium": 12, "low": 5, "info": 1}


def _rule_based_analysis(change_score: float, findings: list, http_status: Optional[int]) -> dict:
    score = min(change_score, 100) * 0.6
    for f in findings:
        score += SEVERITY_WEIGHTS.get(f.get("severity", "low"), 5)
    if http_status and http_status >= 500:
        score += 15
    score = round(min(score, 100), 1)

    if score >= 75:
        label = "critical"
    elif score >= 50:
        label = "high"
    elif score >= 25:
        label = "medium"
    else:
        label = "low"

    top_findings = sorted(findings, key=lambda f: SEVERITY_WEIGHTS.get(f.get("severity", "low"), 0), reverse=True)[:5]
    remediation_lines = [f"- {f['title']} (severity: {f['severity']})" for f in top_findings]
    if change_score > settings.ANOMALY_THRESHOLD:
        remediation_lines.insert(0, "- Review the content diff below for unauthorized modifications (possible defacement).")

    summary = (
        f"Rule-based assessment: content changed by {change_score}% relative to baseline "
        f"with {len(findings)} security finding(s) detected."
    )
    remediation = "\n".join(remediation_lines) if remediation_lines else "No immediate action items identified."

    return {
        "risk_score": score,
        "risk_label": label,
        "summary": summary,
        "remediation": remediation,
        "source": "rule-based",
    }


def _anthropic_analysis(change_score: float, findings: list, diff_excerpt: str, http_status: Optional[int]) -> Optional[dict]:
    try:
        import anthropic
    except ImportError:
        return None

    if not settings.ANTHROPIC_API_KEY:
        return None

    client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)

    prompt = f"""You are a web security analyst reviewing an automated monitoring result for a website
your organization owns and operates. Assess the situation and respond with ONLY a JSON object
(no markdown fences, no preamble) with exactly these keys:
- "risk_score": integer 0-100
- "risk_label": one of "low", "medium", "high", "critical"
- "summary": 2-3 sentence plain-language summary of what changed / was found
- "remediation": a short prioritized bullet list (as a single string, "\\n" separated) of concrete next steps

Data:
HTTP status: {http_status}
Content change score (0=identical, 100=completely different): {change_score}
Vulnerability/security findings (JSON): {json.dumps(findings)}
Diff excerpt (may be empty if no baseline change):
{diff_excerpt[:3000]}
"""

    try:
        response = client.messages.create(
            model=settings.ANTHROPIC_MODEL,
            max_tokens=600,
            messages=[{"role": "user", "content": prompt}],
        )
        text_blocks = [b.text for b in response.content if getattr(b, "type", None) == "text"]
        raw = "".join(text_blocks).strip()
        raw = raw.strip("`")
        if raw.lower().startswith("json"):
            raw = raw[4:].strip()
        parsed = json.loads(raw)
        return {
            "risk_score": float(parsed.get("risk_score", 0)),
            "risk_label": parsed.get("risk_label", "medium"),
            "summary": parsed.get("summary", ""),
            "remediation": parsed.get("remediation", ""),
            "source": "anthropic",
        }
    except Exception:
        # Any AI/API failure silently falls back to rule-based scoring below.
        return None


def analyze(change_score: float, findings: list, diff_excerpt: str = "", http_status: Optional[int] = None) -> dict:
    ai_result = _anthropic_analysis(change_score, findings, diff_excerpt, http_status)
    if ai_result:
        return ai_result
    return _rule_based_analysis(change_score, findings, http_status)
