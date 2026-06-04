"""Признаки фишинговых ссылок в теле письма (возвращает Finding)."""

from __future__ import annotations

from ..config import Config
from ..models import MessageRecord
from ..rules import RuleRegistry
from ..scoring import Finding
from .util import domain_from_url, is_ip_literal_url, is_punycode, levenshtein


class LinkDetector:
    category = "phishing"

    def __init__(self, config: Config, registry: RuleRegistry):
        self.config = config
        self.registry = registry
        self.cfg = config.body

    def findings(self, rec: MessageRecord) -> list[Finding]:
        if rec.direction == "outbound" or not rec.urls:
            return []
        out: list[Finding] = []
        seen: set[str] = set()

        def add(rule_id: str, reason: str, url: str | None = None) -> None:
            key = rule_id + (url or "")
            if key in seen:
                return
            seen.add(key)
            out.append(Finding(rule_id, "phishing", reason,
                               {"url": url} if url else {}))

        shorteners = self.cfg.get("url_shorteners", [])
        tlds = self.cfg.get("suspicious_tlds", [])

        for url in rec.urls:
            host = domain_from_url(url)
            if is_ip_literal_url(url):
                add("phishing.url_ip_literal", f"ссылка ведёт на IP-адрес ({url})", url)
            if host and host in shorteners:
                add("phishing.url_shortener", f"ссылка через сокращатель ({host})", url)
            if host and any(host.endswith(t) for t in tlds):
                add("phishing.url_suspicious_tld",
                    f"ссылка в подозрительной доменной зоне ({host})", url)
            if is_punycode(host):
                add("phishing.url_punycode", f"домен ссылки в punycode ({host})", url)
            look = self._lookalike(host)
            if look:
                add("phishing.url_lookalike",
                    f"ссылка на домен-двойник «{look}» ({host})", url)

        for text, href in rec.anchors:
            text_host = domain_from_url(text) if "." in text else None
            href_host = domain_from_url(href)
            if text_host and href_host and text_host != href_host:
                add("phishing.url_text_mismatch",
                    f"подмена ссылки: текст «{text_host}», реально ведёт на «{href_host}»",
                    href)

        return out

    def _lookalike(self, domain: str | None) -> str | None:
        if not domain or self.config.is_internal_domain(domain):
            return None
        max_dist = self.config.phishing.get("lookalike_max_distance", 2)
        for internal in self.config.internal_domains:
            if 0 < levenshtein(domain, internal) <= max_dist:
                return internal
        return None
