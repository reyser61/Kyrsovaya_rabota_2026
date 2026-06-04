"""Оценка риска инцидента: модель «Ущерб × Достоверность».

Раньше серьёзность считалась как простая сумма весов -> порог, из-за чего любой
одиночный сигнал создавал инцидент (много ложных срабатываний). Теперь:

  * у каждого правила есть УРОВЕНЬ ДОСТОВЕРНОСТИ (strong / medium / weak);
  * сигналы по письму АГРЕГИРУЮТСЯ в один инцидент на категорию;
  * одиночный слабый сигнал НЕ поднимает тревогу (нужна корреляция);
  * балл считается с ЗАТУХАНИЕМ (стопка слабых сигналов не раздувает риск);
  * серьёзность ОГРАНИЧЕНА достоверностью (critical — только при высокой);
  * письма от/к доверенным партнёрам не алертят на слабых сигналах.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .config import Config
from .models import MessageRecord
from .rules import RuleRegistry

# Коэффициенты затухания для отсортированных по убыванию весов сигналов.
_DIMINISH = [1.0, 0.6, 0.4, 0.25, 0.15]

_SEV_ORDER = ["low", "medium", "high", "critical"]
# Потолок серьёзности в зависимости от достоверности инцидента.
_CONFIDENCE_CAP = {"low": "low", "medium": "high", "high": "critical"}


@dataclass
class Finding:
    """Один сработавший признак (до агрегации в инцидент)."""

    rule_id: str
    category: str
    reason: str
    evidence: dict = field(default_factory=dict)


@dataclass
class Assessment:
    """Итог агрегированной оценки набора признаков одной категории."""

    score: int
    confidence: str            # high / medium / low
    severity: str              # low / medium / high / critical
    triggered_rules: list[str]
    reasons: list[str]
    evidence: dict = field(default_factory=dict)


def _diminished(weights: list[int]) -> int:
    """Сумма весов с затуханием: каждый следующий сигнал учитывается слабее."""
    total = 0.0
    for i, w in enumerate(sorted(weights, reverse=True)):
        total += w * (_DIMINISH[i] if i < len(_DIMINISH) else 0.1)
    return int(round(total))


def _cap_severity(severity: str, cap: str) -> str:
    return severity if _SEV_ORDER.index(severity) <= _SEV_ORDER.index(cap) else cap


def assess(
    findings: list[Finding],
    registry: RuleRegistry,
    config: Config,
    record: MessageRecord,
) -> Assessment | None:
    """Агрегирует признаки одной категории в оценку или None (если подавлено)."""
    active = [f for f in findings if registry.enabled(f.rule_id)]
    if not active:
        return None

    confs = [registry.confidence(f.rule_id) for f in active]
    strong_n = confs.count("strong")
    medium_n = confs.count("medium")
    weak_n = confs.count("weak")
    has_strong = strong_n > 0

    # Allow-list: письма от/к доверенным партнёрам не алертят без сильного сигнала.
    trusted = {d.lower() for d in config.raw.get("trusted_domains", [])}
    involves_trusted = (
        (record.from_domain in trusted)
        or any(d in trusted for d in record.recipient_domains)
    )
    if involves_trusted and not has_strong:
        return None

    # Порог тревоги: одиночный слабый сигнал не создаёт инцидент.
    if not has_strong and medium_n == 0 and weak_n < 2:
        return None

    # Достоверность инцидента.
    if has_strong and len(active) >= 2:
        confidence = "high"
    elif has_strong or medium_n >= 2 or (medium_n >= 1 and weak_n >= 1):
        confidence = "medium"
    else:
        confidence = "low"

    score = _diminished([registry.weight(f.rule_id) for f in active])
    severity = _cap_severity(
        config.severity_for_score(score), _CONFIDENCE_CAP[confidence]
    )

    evidence: dict = {}
    for f in active:
        evidence.update(f.evidence)

    return Assessment(
        score=score,
        confidence=confidence,
        severity=severity,
        triggered_rules=[f.rule_id for f in active],
        reasons=[f.reason for f in active],
        evidence=evidence,
    )
