"""Тесты парсеров Postfix и Dovecot."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mailguard.config import Config
from mailguard.parsers import DovecotParser, PostfixParser

CONFIG = Config(raw={"internal_domains": ["corp-mail.ru"], "free_mail_domains": []})

POSTFIX_SAMPLE = """\
Jun  2 10:15:32 mail postfix/smtpd[111]: connect from mx.bad.tld[203.0.113.45]
Jun  2 10:15:33 mail postfix/smtpd[111]: A1B2C3D4E5: client=mx.bad.tld[203.0.113.45], helo=<mx.bad.tld>
Jun  2 10:15:33 mail postfix/cleanup[112]: A1B2C3D4E5: message-id=<x@bad.tld>
Jun  2 10:15:33 mail postfix/cleanup[112]: A1B2C3D4E5: warning: header Subject: Срочно подтвердите from mx.bad.tld[203.0.113.45]
Jun  2 10:15:33 mail opendmarc[113]: A1B2C3D4E5: SPF(mailfrom): fail
Jun  2 10:15:33 mail opendmarc[113]: A1B2C3D4E5: DKIM: fail
Jun  2 10:15:33 mail opendmarc[113]: A1B2C3D4E5: DMARC: fail
Jun  2 10:15:34 mail postfix/qmgr[114]: A1B2C3D4E5: from=<ceo@corp-mail.ru>, size=4200, nrcpt=1 (queue active)
Jun  2 10:15:34 mail postfix/smtp[115]: A1B2C3D4E5: to=<buh@corp-mail.ru>, relay=local, delay=0.5, status=sent (250 OK)
"""

DOVECOT_SAMPLE = """\
Jun  2 10:20:01 mail dovecot: imap-login: Login: user=<alice@corp-mail.ru>, method=PLAIN, rip=192.0.2.10, lip=10.0.0.5, mpid=2345, TLS, session=<abc>
Jun  2 10:20:05 mail dovecot: imap-login: Disconnected (auth failed, 3 attempts in 2 secs): user=<bob@corp-mail.ru>, method=PLAIN, rip=198.51.100.7, lip=10.0.0.5
"""


class TestPostfixParser(unittest.TestCase):
    def setUp(self):
        self.parser = PostfixParser(CONFIG)
        self.messages = self.parser.parse_lines(POSTFIX_SAMPLE.splitlines())

    def test_single_message(self):
        self.assertEqual(len(self.messages), 1)

    def test_fields(self):
        m = self.messages[0]
        self.assertEqual(m.queue_id, "A1B2C3D4E5")
        self.assertEqual(m.client_ip, "203.0.113.45")
        self.assertEqual(m.from_addr, "ceo@corp-mail.ru")
        self.assertEqual(m.to_addrs, ["buh@corp-mail.ru"])
        self.assertEqual(m.size, 4200)
        self.assertEqual(m.nrcpt, 1)
        self.assertEqual(m.status, "sent")
        self.assertEqual(m.spf, "fail")
        self.assertEqual(m.dkim, "fail")
        self.assertEqual(m.dmarc, "fail")
        self.assertEqual(m.helo, "mx.bad.tld")
        self.assertIn("Срочно", m.subject)

    def test_direction_inbound(self):
        # from внутреннего домена, но без sasl — это спуфинг, направление inbound
        self.assertEqual(self.messages[0].direction, "inbound")

    def test_from_domain(self):
        self.assertEqual(self.messages[0].from_domain, "corp-mail.ru")


class TestDovecotParser(unittest.TestCase):
    def setUp(self):
        self.events = DovecotParser().parse_lines(DOVECOT_SAMPLE.splitlines())

    def test_count(self):
        self.assertEqual(len(self.events), 2)

    def test_login(self):
        login = self.events[0]
        self.assertEqual(login.result, "login")
        self.assertEqual(login.user, "alice@corp-mail.ru")
        self.assertEqual(login.rip, "192.0.2.10")
        self.assertTrue(login.tls)

    def test_fail(self):
        fail = self.events[1]
        self.assertEqual(fail.result, "auth_failed")
        self.assertEqual(fail.attempts, 3)
        self.assertEqual(fail.rip, "198.51.100.7")


if __name__ == "__main__":
    unittest.main()
