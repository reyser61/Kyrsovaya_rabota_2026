"""Тесты блок-листа IoC и детектора совпадений (этап D)."""

import os
import sys
import tempfile
import unittest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mailguard.blocklist import Blocklist
from mailguard.config import load_config
from mailguard.detectors import IocMatchDetector
from mailguard.models import Attachment, MessageRecord
from mailguard.rules import RuleRegistry

CONFIG = load_config()


def reg() -> RuleRegistry:
    d = tempfile.mkdtemp()
    return RuleRegistry(CONFIG, declarative_path=os.path.join(d, "r.yaml"),
                        state_path=os.path.join(d, "s.json"))


def blocklist(entries) -> Blocklist:
    path = os.path.join(tempfile.mkdtemp(), "bl.csv")
    bl = Blocklist(path)
    bl.add_many(entries)
    return bl


def rec(**kw) -> MessageRecord:
    base = dict(timestamp=datetime(2026, 6, 2, 12, 0), direction="inbound")
    base.update(kw)
    return MessageRecord(**base)


class TestBlocklist(unittest.TestCase):
    def test_add_and_persist(self):
        path = os.path.join(tempfile.mkdtemp(), "bl.csv")
        bl = Blocklist(path)
        self.assertTrue(bl.add("ip", "1.2.3.4", "test"))
        self.assertFalse(bl.add("ip", "1.2.3.4"))   # дубликат
        bl.save()
        self.assertEqual(Blocklist(path).count(), 1)   # перечитали с диска

    def test_domain_subdomain_match(self):
        bl = blocklist([("domain", "evil.ru", "t")])
        self.assertIsNotNone(bl.match_domain("sub.evil.ru"))
        self.assertIsNone(bl.match_domain("notevil.ru"))

    def test_subject_substring(self):
        bl = blocklist([("subject", "подтвердите учетную запись", "t")])
        self.assertIsNotNone(bl.match_subject("СРОЧНО: Подтвердите учетную запись!"))


class TestIocMatchDetector(unittest.TestCase):
    def test_ip_and_domain_match(self):
        bl = blocklist([("ip", "9.9.9.9", "ti"), ("domain", "evil.ru", "ti")])
        det = IocMatchDetector(CONFIG, reg(), bl)
        r = rec(client_ip="9.9.9.9", from_addr="a@evil.ru",
                urls=["http://sub.evil.ru/x"])
        ids = {f.rule_id for f in det.findings(r)}
        self.assertIn("ioc.match_ip", ids)
        self.assertIn("ioc.match_domain", ids)

    def test_hash_match(self):
        bl = blocklist([("file_sha256", "a" * 64, "ti")])
        det = IocMatchDetector(CONFIG, reg(), bl)
        r = rec(attachments=[Attachment("x.exe", sha256="a" * 64)])
        self.assertIn("ioc.match_file_hash", {f.rule_id for f in det.findings(r)})

    def test_no_match_empty(self):
        det = IocMatchDetector(CONFIG, reg(), blocklist([]))
        self.assertEqual(det.findings(rec(client_ip="9.9.9.9")), [])


if __name__ == "__main__":
    unittest.main()
