"""Тесты модели оценки риска (достоверность, агрегация, подавление, allow-list)."""

import os
import sys
import tempfile
import unittest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mailguard.config import load_config
from mailguard.models import MessageRecord
from mailguard.rules import RuleRegistry
from mailguard.scoring import Finding, assess

CONFIG = load_config()


def reg() -> RuleRegistry:
    d = tempfile.mkdtemp()
    return RuleRegistry(CONFIG, declarative_path=os.path.join(d, "r.yaml"),
                        state_path=os.path.join(d, "s.json"))


def rec(**kw) -> MessageRecord:
    base = dict(timestamp=datetime(2026, 6, 2, 12, 0), from_addr="x@bad.tld",
                to_addrs=["u@corp-mail.ru"], direction="inbound")
    base.update(kw)
    return MessageRecord(**base)


def F(rule_id, cat="phishing"):
    return Finding(rule_id, cat, "тест")


class TestSuppression(unittest.TestCase):
    def test_single_weak_suppressed(self):
        self.assertIsNone(assess([F("phishing.helo_mismatch")], reg(), CONFIG, rec()))

    def test_two_weak_alerts_low(self):
        a = assess([F("phishing.helo_mismatch"), F("phishing.spf_fail")],
                   reg(), CONFIG, rec())
        self.assertIsNotNone(a)
        self.assertEqual(a.confidence, "low")
        self.assertEqual(a.severity, "low")   # ограничено достоверностью

    def test_single_strong_medium_conf(self):
        a = assess([F("phishing.spoofed_internal")], reg(), CONFIG, rec())
        self.assertEqual(a.confidence, "medium")

    def test_strong_plus_more_high_conf(self):
        a = assess([F("phishing.spoofed_internal"), F("phishing.dmarc_fail")],
                   reg(), CONFIG, rec())
        self.assertEqual(a.confidence, "high")
        self.assertIn(a.severity, {"high", "critical"})

    def test_single_medium_low_conf(self):
        a = assess([F("phishing.dmarc_fail")], reg(), CONFIG, rec())
        self.assertEqual(a.confidence, "low")


class TestAllowList(unittest.TestCase):
    def test_trusted_suppresses_weak(self):
        r = rec(from_addr="user@corp-mail.ru", to_addrs=["x@partner.com"],
                direction="outbound")
        # partner.com — доверенный; слабый сигнал не алертит
        self.assertIsNone(assess([F("dlp.attachment_office", "dlp")],
                                 reg(), CONFIG, r))

    def test_trusted_does_not_suppress_strong(self):
        r = rec(from_addr="user@corp-mail.ru", to_addrs=["x@partner.com"],
                direction="outbound")
        a = assess([F("dlp.pii", "dlp")], reg(), CONFIG, r)
        self.assertIsNotNone(a)


class TestDiminishing(unittest.TestCase):
    def test_stacking_weak_does_not_explode(self):
        # пять слабых сигналов не должны давать критическую серьёзность
        weak = [F("phishing.helo_mismatch"), F("phishing.spf_fail"),
                F("phishing.mass_recipients"), F("phishing.url_shortener"),
                F("phishing.url_suspicious_tld")]
        a = assess(weak, reg(), CONFIG, rec())
        self.assertEqual(a.confidence, "low")
        self.assertEqual(a.severity, "low")


if __name__ == "__main__":
    unittest.main()
