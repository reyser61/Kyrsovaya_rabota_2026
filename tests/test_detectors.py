"""Тесты детекторов (поставщиков признаков) на единой записи MessageRecord."""

import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mailguard.config import load_config
from mailguard.detectors import (
    AccountDetector,
    AttachmentDetector,
    ContentDetector,
    DlpDetector,
    LinkDetector,
    PhishingDetector,
)
from mailguard.models import Attachment, ImapEvent, MessageRecord
from mailguard.rules import RuleRegistry

CONFIG = load_config()
VALID_CARD = "4111 1111 1111 1111"


def registry() -> RuleRegistry:
    d = tempfile.mkdtemp()
    return RuleRegistry(CONFIG, declarative_path=os.path.join(d, "r.yaml"),
                        state_path=os.path.join(d, "s.json"))


def rec(**kw) -> MessageRecord:
    base = dict(timestamp=datetime(2026, 6, 2, 12, 0, 0))
    base.update(kw)
    return MessageRecord(**base)


def rule_ids(findings):
    return {f.rule_id for f in findings}


class TestPhishingSignals(unittest.TestCase):
    def setUp(self):
        self.det = PhishingDetector(CONFIG, registry())

    def test_auth_and_spoof(self):
        r = rec(from_addr="ceo@corp-mail.ru", client_ip="91.214.124.77",
                direction="inbound", spf="fail", dkim="fail", dmarc="fail",
                to_addrs=["buh@corp-mail.ru"])
        ids = rule_ids(self.det.findings(r))
        self.assertIn("phishing.spoofed_internal", ids)
        self.assertIn("phishing.dmarc_fail", ids)

    def test_lookalike(self):
        r = rec(from_addr="support@corp-maill.ru", direction="inbound")
        self.assertIn("phishing.lookalike_sender", rule_ids(self.det.findings(r)))

    def test_replyto(self):
        r = rec(from_addr="a@partner.com", reply_to="evil@bad.tld", direction="inbound")
        self.assertIn("phishing.replyto_mismatch", rule_ids(self.det.findings(r)))

    def test_outbound_empty(self):
        r = rec(from_addr="u@corp-mail.ru", direction="outbound", dmarc="fail")
        self.assertEqual(self.det.findings(r), [])


class TestContentSubjectAndBody(unittest.TestCase):
    def setUp(self):
        self.det = ContentDetector(CONFIG, registry())

    def test_manipulation_subject_only(self):
        r = rec(subject="Срочно подтвердите, иначе блокировка", direction="inbound")
        self.assertIn("phishing.manipulative_content", rule_ids(self.det.findings(r)))

    def test_manipulation_body_only(self):
        r = rec(subject="Привет",
                body_text="Срочно войдите и введите пароль, иначе блокировка",
                direction="inbound")
        ids = rule_ids(self.det.findings(r))
        self.assertIn("phishing.manipulative_content", ids)
        self.assertIn("phishing.credential_request", ids)

    def test_pii_body_outbound(self):
        r = rec(body_text=f"Карта {VALID_CARD}", from_addr="u@corp-mail.ru",
                to_addrs=["x@gmail.com"], direction="outbound")
        self.assertIn("dlp.pii", rule_ids(self.det.findings(r)))

    def test_secret_body_outbound(self):
        r = rec(body_text="-----BEGIN RSA PRIVATE KEY-----\nMIIE",
                from_addr="u@corp-mail.ru", to_addrs=["x@gmail.com"],
                direction="outbound")
        self.assertIn("dlp.secret_exposure", rule_ids(self.det.findings(r)))

    def test_internal_outbound_no_dlp(self):
        r = rec(subject=f"Конфиденциально {VALID_CARD}", from_addr="u@corp-mail.ru",
                to_addrs=["c@corp-mail.ru"], direction="outbound")
        self.assertEqual([f for f in self.det.findings(r) if f.category == "dlp"], [])


class TestLinks(unittest.TestCase):
    def setUp(self):
        self.det = LinkDetector(CONFIG, registry())

    def test_ip_mismatch_punycode(self):
        r = rec(direction="inbound", from_addr="x@bad.tld",
                urls=["http://93.184.216.34/x", "https://xn--80ak6aa92e.com/y"],
                anchors=[("online.corp-mail.ru", "http://evil.ru/z")])
        ids = rule_ids(self.det.findings(r))
        self.assertIn("phishing.url_ip_literal", ids)
        self.assertIn("phishing.url_punycode", ids)
        self.assertIn("phishing.url_text_mismatch", ids)


class TestAttachments(unittest.TestCase):
    def setUp(self):
        self.det = AttachmentDetector(CONFIG, registry())

    def test_double_ext(self):
        r = rec(direction="inbound", from_addr="x@bad.tld",
                attachments=[Attachment("Счет.pdf.exe", size=100)])
        self.assertIn("phishing.attachment_double_ext", rule_ids(self.det.findings(r)))

    def test_real_macro(self):
        r = rec(direction="inbound", from_addr="x@bad.tld",
                attachments=[Attachment("Договор.docx", size=100, has_macro=True)])
        self.assertIn("phishing.attachment_real_macro", rule_ids(self.det.findings(r)))

    def test_archive_inner(self):
        r = rec(direction="inbound", from_addr="x@bad.tld",
                attachments=[Attachment("a.zip", size=100, inner_files=["p.exe"])])
        self.assertIn("phishing.attachment_archive_inner", rule_ids(self.det.findings(r)))

    def test_plain_archive_is_weak_only(self):
        r = rec(direction="inbound", from_addr="x@bad.tld",
                attachments=[Attachment("photos.zip", size=100)])
        self.assertEqual(rule_ids(self.det.findings(r)), {"phishing.attachment_archive"})

    def test_office_vs_highrisk(self):
        r = rec(direction="outbound", from_addr="u@corp-mail.ru",
                to_addrs=["x@gmail.com"],
                attachments=[Attachment("report.xlsx", size=100),
                             Attachment("dump.sql", size=100)])
        ids = rule_ids(self.det.findings(r))
        self.assertIn("dlp.attachment_office", ids)
        self.assertIn("dlp.attachment_highrisk", ids)


class TestDlpMeta(unittest.TestCase):
    def setUp(self):
        self.det = DlpDetector(CONFIG, registry())

    def test_free_mail(self):
        r = rec(from_addr="u@corp-mail.ru", to_addrs=["x@gmail.com"], direction="outbound")
        self.assertIn("dlp.free_mail_recipient", rule_ids(self.det.findings(r)))

    def test_exfiltration(self):
        recs = [rec(from_addr="a@corp-mail.ru", to_addrs=["c@gmail.com"],
                    direction="outbound") for _ in range(12)]
        inc = self.det.exfiltration(recs)
        self.assertTrue(any(i.rule_id == "dlp.exfiltration" for i in inc))
        self.assertEqual(inc[0].confidence, "high")


class TestAccount(unittest.TestCase):
    def setUp(self):
        self.det = AccountDetector(CONFIG, registry())

    def test_bruteforce_takeover(self):
        t = datetime(2026, 6, 2, 2, 0, 0)
        ev = [ImapEvent(timestamp=t + timedelta(seconds=40 * i), user="b@corp-mail.ru",
                        rip="185.220.101.45", result="auth_failed", attempts=i + 1)
              for i in range(7)]
        ev.append(ImapEvent(timestamp=t + timedelta(minutes=6), user="b@corp-mail.ru",
                            rip="185.220.101.45", result="login"))
        incs = self.det.analyze(ev)
        rules = {i.rule_id for i in incs}
        self.assertIn("account.bruteforce", rules)
        self.assertIn("account.takeover", rules)
        self.assertTrue(all(i.confidence in {"high", "medium", "low"} for i in incs))


if __name__ == "__main__":
    unittest.main()
