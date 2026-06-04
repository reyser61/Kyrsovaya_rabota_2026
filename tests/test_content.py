"""Тесты парсера .eml (хэши, инспекция zip, Reply-To) и корреляции в движке."""

import io
import os
import sys
import tempfile
import unittest
import zipfile
from email.message import EmailMessage as PyEmail

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mailguard.config import load_config
from mailguard.engine import Engine
from mailguard.models import EmailMessage, MailMessage
from mailguard.parsers import EmlParser
from mailguard.rules import RuleRegistry

CONFIG = load_config()


def make_registry() -> RuleRegistry:
    d = tempfile.mkdtemp()
    return RuleRegistry(CONFIG, declarative_path=os.path.join(d, "r.yaml"),
                        state_path=os.path.join(d, "s.json"))


class TestEmlParser(unittest.TestCase):
    def setUp(self):
        self.parser = EmlParser(CONFIG)

    def _write(self, msg: PyEmail) -> str:
        fh = tempfile.NamedTemporaryFile(suffix=".eml", delete=False)
        fh.write(msg.as_bytes())
        fh.close()
        return fh.name

    def test_attachment_hash(self):
        m = PyEmail()
        m["From"] = "a@evil.tld"
        m["To"] = "u@corp-mail.ru"
        m["Subject"] = "test"
        m.set_content("body")
        m.add_attachment(b"hello", maintype="application", subtype="octet-stream",
                         filename="x.bin")
        path = self._write(m)
        try:
            e = self.parser.parse_file(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(e.attachments), 1)
        self.assertIsNotNone(e.attachments[0].sha256)
        self.assertEqual(len(e.attachments[0].sha256), 64)

    def test_zip_inspection(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("invoice.exe", b"MZ payload")
        m = PyEmail()
        m["From"] = "a@evil.tld"
        m["To"] = "u@corp-mail.ru"
        m["Subject"] = "test"
        m.set_content("see attachment")
        m.add_attachment(buf.getvalue(), maintype="application", subtype="zip",
                         filename="arc.zip")
        path = self._write(m)
        try:
            e = self.parser.parse_file(path)
        finally:
            os.unlink(path)
        self.assertIn("invoice.exe", e.attachments[0].inner_files)

    def test_reply_to(self):
        m = PyEmail()
        m["From"] = "a@partner.com"
        m["Reply-To"] = "attacker@evil.tld"
        m["To"] = "u@corp-mail.ru"
        m["Subject"] = "test"
        m.set_content("body")
        path = self._write(m)
        try:
            e = self.parser.parse_file(path)
        finally:
            os.unlink(path)
        self.assertEqual(e.reply_to, "attacker@evil.tld")


class TestCorrelation(unittest.TestCase):
    def test_merge_by_message_id(self):
        engine = Engine(CONFIG, make_registry())
        mail = MailMessage(queue_id="Q1", message_id="abc@mail", subject="Тема",
                           from_addr="x@bad.tld", to_addrs=["u@corp-mail.ru"],
                           direction="inbound")
        email = EmailMessage(message_id="<abc@mail>", body_text="Тело письма",
                             from_addr="x@bad.tld", to_addrs=["u@corp-mail.ru"],
                             direction="inbound")
        records = engine._build_records([mail], [email])
        self.assertEqual(len(records), 1)
        r = records[0]
        self.assertIn("postfix", r.sources)
        self.assertIn("eml", r.sources)
        self.assertEqual(r.subject, "Тема")
        self.assertEqual(r.body_text, "Тело письма")

    def test_no_match_keeps_separate(self):
        engine = Engine(CONFIG, make_registry())
        mail = MailMessage(queue_id="Q1", message_id="one@mail",
                           from_addr="x@bad.tld", direction="inbound")
        email = EmailMessage(message_id="<two@mail>", body_text="t",
                             from_addr="y@bad.tld", direction="inbound")
        records = engine._build_records([mail], [email])
        self.assertEqual(len(records), 2)


if __name__ == "__main__":
    unittest.main()
