"""Тесты утилит: валидация ПДн, манипулятивные паттерны, URL."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mailguard.detectors.util import (
    domain_from_url,
    find_pii,
    inn_valid,
    is_ip_literal_url,
    is_punycode,
    luhn_valid,
    manipulation_categories,
    snils_valid,
)


class TestValidators(unittest.TestCase):
    def test_luhn(self):
        self.assertTrue(luhn_valid("4111 1111 1111 1111"))   # валидная тест-карта
        self.assertFalse(luhn_valid("4111 1111 1111 1112"))  # испорченная

    def test_snils(self):
        self.assertTrue(snils_valid("112-233-445 95"))
        self.assertFalse(snils_valid("112-233-445 96"))

    def test_inn(self):
        self.assertTrue(inn_valid("7830002293"))     # известный валидный ИНН (10)
        self.assertFalse(inn_valid("7830002294"))

    def test_find_pii_valid_card(self):
        self.assertIn("credit_card", find_pii("оплата 4111 1111 1111 1111"))

    def test_find_pii_rejects_invalid_card(self):
        # случайные 16 цифр, не проходящие Луна, не должны попасть в карты
        self.assertNotIn("credit_card", find_pii("1234 5678 9012 3456"))

    def test_find_secret(self):
        self.assertIn("private_key",
                      find_pii("-----BEGIN RSA PRIVATE KEY-----\nMIIE..."))


class TestManipulation(unittest.TestCase):
    def test_categories(self):
        cats = manipulation_categories(
            "Срочно подтвердите учётную запись, иначе будет заблокирована")
        self.assertIn("urgency", cats)
        self.assertIn("action", cats)
        self.assertIn("threat", cats)

    def test_empty(self):
        self.assertEqual(manipulation_categories("обычное письмо про погоду"), [])


class TestUrl(unittest.TestCase):
    def test_domain_from_url(self):
        self.assertEqual(domain_from_url("https://user@Site.COM:8080/path?x=1"), "site.com")

    def test_ip_literal(self):
        self.assertTrue(is_ip_literal_url("http://93.184.216.34/secure"))
        self.assertFalse(is_ip_literal_url("http://example.com"))

    def test_punycode(self):
        self.assertTrue(is_punycode("xn--80ak6aa92e.com"))
        self.assertFalse(is_punycode("example.com"))


if __name__ == "__main__":
    unittest.main()
