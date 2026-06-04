"""Детектор компрометации аккаунтов по логам IMAP (Dovecot).

Компрометация почтового ящика — частое следствие успешного фишинга, поэтому
этот детектор дополняет анализ. Признаки:
  * брутфорс: много неудачных входов с одного IP за короткое окно;
  * успешный вход с того же IP сразу после серии неудачных (захват ящика);
  * «невозможное перемещение»: вход одного пользователя из разных подсетей
    за короткий промежуток времени;
  * вход без TLS (передача пароля в открытом виде).
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from ..config import Config
from ..models import ImapEvent, Incident
from ..narrative import build_account_description, build_account_summary
from ..rules import RuleRegistry

# достоверность инцидента по достоверности правила
_CONF = {"strong": "high", "medium": "medium", "weak": "low"}


class AccountDetector:
    category = "account"

    def __init__(self, config: Config, registry: RuleRegistry):
        self.config = config
        self.registry = registry
        self.cfg = config.account

    def analyze(self, events: list[ImapEvent]) -> list[Incident]:
        events = [e for e in events if e.timestamp is not None]
        events.sort(key=lambda e: e.timestamp)
        incidents: list[Incident] = []
        incidents.extend(self._bruteforce_and_takeover(events))
        incidents.extend(self._impossible_travel(events))
        incidents.extend(self._plaintext(events))
        return incidents

    # ------------------------------------------------------------------ #

    def _bruteforce_and_takeover(self, events: list[ImapEvent]) -> list[Incident]:
        out: list[Incident] = []
        window = timedelta(minutes=self.cfg.get("bruteforce_window_min", 10))
        threshold = self.cfg.get("bruteforce_failures", 5)

        # группируем неудачные входы по IP
        fails_by_ip: dict[str, list[ImapEvent]] = defaultdict(list)
        for e in events:
            if e.result == "auth_failed" and e.rip:
                fails_by_ip[e.rip].append(e)

        flagged_ips: dict[str, ImapEvent] = {}  # ip -> последнее неудачное событие серии
        for ip, fails in fails_by_ip.items():
            # скользящее окно подсчёта
            for i in range(len(fails)):
                window_fails = [
                    f for f in fails
                    if 0 <= (f.timestamp - fails[i].timestamp).total_seconds() <= window.total_seconds()
                ]
                if len(window_fails) >= threshold:
                    last = window_fails[-1]
                    flagged_ips[ip] = last
                    if self.registry.enabled("account.bruteforce"):
                        score = self.registry.weight("account.bruteforce") + \
                            min(len(window_fails) - threshold, 15)
                        users = sorted({f.user for f in window_fails})
                        out.append(
                            Incident(
                                timestamp=last.timestamp,
                                category=self.category,
                                rule_id="account.bruteforce",
                                title=f"Брутфорс IMAP с {ip}",
                                description=build_account_description(
                                    "",
                                    f"С адреса {ip} зафиксировано {len(window_fails)} "
                                    f"неудачных попыток входа за "
                                    f"{self.cfg.get('bruteforce_window_min', 10)} мин по "
                                    f"учётным записям: {', '.join(users)}. Это характерно "
                                    f"для подбора пароля (брутфорса)"),
                                score=score,
                                severity=self.config.severity_for_score(score),
                                confidence=_CONF[self.registry.confidence("account.bruteforce")],
                                origin="IMAP",
                                summary=build_account_summary(
                                    f"Брутфорс IMAP с {ip} "
                                    f"({len(window_fails)} попыток)",
                                    _CONF[self.registry.confidence("account.bruteforce")]),
                                source=ip,
                                evidence={
                                    "ip": ip,
                                    "failures": len(window_fails),
                                    "users": users,
                                    "triggered_rules": ["account.bruteforce"],
                                },
                            )
                        )
                    break

        # успешный вход с «брутфорсного» IP после серии неудач = захват
        if self.registry.enabled("account.takeover"):
            for e in events:
                if e.result == "login" and e.rip in flagged_ips:
                    fail_time = flagged_ips[e.rip].timestamp
                    if 0 <= (e.timestamp - fail_time).total_seconds() <= window.total_seconds() * 3:
                        score = self.registry.weight("account.takeover")
                        out.append(
                            Incident(
                                timestamp=e.timestamp,
                                category=self.category,
                                rule_id="account.takeover",
                                title=f"Захват ящика {e.user}",
                                description=build_account_description(
                                    "",
                                    f"Учётная запись {e.user}: успешный вход с {e.rip} "
                                    f"произошёл сразу после серии неудачных попыток. Это "
                                    f"указывает на вероятный успешный подбор пароля и "
                                    f"компрометацию ящика"),
                                score=score,
                                severity=self.config.severity_for_score(score),
                                confidence=_CONF[self.registry.confidence("account.takeover")],
                                origin="IMAP",
                                summary=build_account_summary(
                                    f"Захват ящика {e.user} после брутфорса",
                                    _CONF[self.registry.confidence("account.takeover")]),
                                source=e.user,
                                evidence={"ip": e.rip, "user": e.user,
                                          "triggered_rules": ["account.takeover"]},
                            )
                        )
        return out

    def _impossible_travel(self, events: list[ImapEvent]) -> list[Incident]:
        out: list[Incident] = []
        if not self.registry.enabled("account.impossible_travel"):
            return out
        logins_by_user: dict[str, list[ImapEvent]] = defaultdict(list)
        for e in events:
            if e.result == "login" and e.rip:
                logins_by_user[e.user].append(e)

        for user, logins in logins_by_user.items():
            logins.sort(key=lambda e: e.timestamp)
            for prev, cur in zip(logins, logins[1:]):
                if self._net(prev.rip) == self._net(cur.rip):
                    continue
                gap = (cur.timestamp - prev.timestamp).total_seconds()
                if gap <= 3600:  # вход из двух разных сетей в течение часа
                    score = self.registry.weight("account.impossible_travel")
                    out.append(
                        Incident(
                            timestamp=cur.timestamp,
                            category=self.category,
                            rule_id="account.impossible_travel",
                            title=f"Подозрительная гео-смена для {user}",
                            description=build_account_description(
                                "",
                                f"Учётная запись {user} входила из разных сетей "
                                f"({prev.rip} и {cur.rip}) с интервалом всего "
                                f"{int(gap // 60)} мин — физически невозможное "
                                f"перемещение, возможен доступ постороннего"),
                            score=score,
                            severity=self.config.severity_for_score(score),
                            confidence=_CONF[self.registry.confidence("account.impossible_travel")],
                            origin="IMAP",
                            summary=build_account_summary(
                                f"Невозможное перемещение: {user}",
                                _CONF[self.registry.confidence("account.impossible_travel")]),
                            source=user,
                            evidence={
                                "user": user,
                                "ip_1": prev.rip,
                                "ip_2": cur.rip,
                                "gap_seconds": int(gap),
                                "triggered_rules": ["account.impossible_travel"],
                            },
                        )
                    )
        return out

    def _plaintext(self, events: list[ImapEvent]) -> list[Incident]:
        if not self.cfg.get("flag_plaintext_login", True):
            return []
        if not self.registry.enabled("account.plaintext_login"):
            return []
        out: list[Incident] = []
        for e in events:
            if e.result == "login" and not e.tls:
                score = self.registry.weight("account.plaintext_login")
                out.append(
                    Incident(
                        timestamp=e.timestamp,
                        category=self.category,
                        rule_id="account.plaintext_login",
                        title=f"Вход без TLS: {e.user}",
                        description=build_account_description(
                            "",
                            f"Учётная запись {e.user} вошла с {e.rip} без шифрования "
                            f"TLS — пароль мог быть перехвачен в открытом виде",
                            recommendation=False),
                        score=score,
                        severity=self.config.severity_for_score(score),
                        confidence=_CONF[self.registry.confidence("account.plaintext_login")],
                        origin="IMAP",
                        summary=build_account_summary(
                            f"Вход без TLS: {e.user}",
                            _CONF[self.registry.confidence("account.plaintext_login")]),
                        source=e.user,
                        evidence={"user": e.user, "ip": e.rip, "method": e.method,
                                  "triggered_rules": ["account.plaintext_login"]},
                    )
                )
        return out

    @staticmethod
    def _net(ip: str | None) -> str | None:
        """Грубая «сеть» = первые три октета IPv4 (для импоссибл-травела)."""
        if not ip or ":" in ip:
            return ip
        parts = ip.split(".")
        return ".".join(parts[:3]) if len(parts) == 4 else ip
