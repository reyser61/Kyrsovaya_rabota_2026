"""Тесты сбора IoC: отбор по серьёзности, дедупликация, типы."""

import os
import sys
import unittest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mailguard.config import load_config
from mailguard.ioc import IocCollector
from mailguard.models import Attachment, Incident, MessageRecord

CONFIG = load_config()


def incident(severity="high", category="phishing", **kw):
    base = dict(timestamp=datetime(2026, 6, 2, 12, 0), category=category,
                rule_id="phishing.composite", title="t", description="d",
                score=80, severity=severity, confidence="high", source="x@bad.tld")
    base.update(kw)
    return Incident(**base)


def record(**kw):
    base = dict(from_addr="x@bad.tld", client_ip="9.9.9.9", direction="inbound",
                urls=["http://evil.ru/a"], subject="Срочно")
    base.update(kw)
    return MessageRecord(**base)


class TestIocCollector(unittest.TestCase):
    def test_high_severity_collected(self):
        c = IocCollector(CONFIG)
        c.consider(incident("high"), record(
            attachments=[Attachment("x.exe", sha256="a" * 64)]))
        types = {i.type for i in c.result()}
        self.assertIn("ip", types)
        self.assertIn("sender_email", types)
        self.assertIn("sender_domain", types)
        self.assertIn("url_domain", types)
        self.assertIn("file_sha256", types)

    def test_low_severity_skipped(self):
        c = IocCollector(CONFIG)
        c.consider(incident("medium"), record())
        self.assertEqual(c.result(), [])

    def test_dedup_and_count(self):
        c = IocCollector(CONFIG)
        c.consider(incident("high"), record())
        c.consider(incident("critical"), record())
        ips = [i for i in c.result() if i.type == "ip"]
        self.assertEqual(len(ips), 1)
        self.assertEqual(ips[0].count, 2)
        self.assertEqual(ips[0].max_severity, "critical")


if __name__ == "__main__":
    unittest.main()
