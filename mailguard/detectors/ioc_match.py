"""Детектор совпадений индикаторов письма с блок-листом IoC (этап D).

Сверяет IP, отправителя, домены (отправителя и из ссылок), хэши вложений и тему
письма с базой известных вредоносных индикаторов. Совпадение — сильный сигнал.
"""

from __future__ import annotations

from ..blocklist import Blocklist
from ..config import Config
from ..models import MessageRecord
from ..rules import RuleRegistry
from ..scoring import Finding
from .util import domain_from_url


class IocMatchDetector:
    category = "phishing"

    def __init__(self, config: Config, registry: RuleRegistry,
                 blocklist: Blocklist):
        self.config = config
        self.registry = registry
        self.blocklist = blocklist

    def findings(self, rec: MessageRecord) -> list[Finding]:
        bl = self.blocklist
        if bl.count() == 0:
            return []
        out: list[Finding] = []
        seen: set[str] = set()

        def add(rule_id: str, reason: str, value: str, entry) -> None:
            if rule_id + value in seen:
                return
            seen.add(rule_id + value)
            out.append(Finding(rule_id, "phishing", reason,
                               {"ioc_value": value, "ioc_source": entry.source}))

        def src(e) -> str:
            return f" (блок-лист IoC, источник: {e.source})" if e.source else " (блок-лист IoC)"

        e = bl.match("ip", rec.client_ip)
        if e:
            add("ioc.match_ip", f"IP {rec.client_ip} в списке вредоносных{src(e)}",
                rec.client_ip, e)

        e = bl.match("email", rec.from_addr)
        if e:
            add("ioc.match_email",
                f"отправитель {rec.from_addr} в списке вредоносных{src(e)}",
                rec.from_addr, e)

        e = bl.match_domain(rec.from_domain)
        if e:
            add("ioc.match_domain",
                f"домен отправителя {rec.from_domain} в списке вредоносных{src(e)}",
                rec.from_domain, e)

        for url in rec.urls:
            host = domain_from_url(url)
            e = bl.match_domain(host)
            if e:
                add("ioc.match_domain",
                    f"домен ссылки {host} в списке вредоносных{src(e)}", host, e)

        for att in rec.attachments:
            e = bl.match("file_sha256", att.sha256)
            if e:
                add("ioc.match_file_hash",
                    f"хэш вложения «{att.filename}» совпал с вредоносным образцом"
                    f"{src(e)}", att.sha256, e)

        e = bl.match_subject(rec.subject)
        if e:
            add("ioc.match_subject",
                f"тема совпадает с известной кампанией{src(e)}", e.value, e)

        return out
