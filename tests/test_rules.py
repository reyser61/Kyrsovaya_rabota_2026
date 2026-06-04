"""Тесты реестра правил: загрузка, веса из config, вкл/выкл, декларативные."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mailguard.config import load_config
from mailguard.rules import Rule, RuleRegistry

CONFIG = load_config()


def fresh_registry() -> RuleRegistry:
    d = tempfile.mkdtemp()
    return RuleRegistry(
        CONFIG,
        declarative_path=os.path.join(d, "rules.yaml"),
        state_path=os.path.join(d, "state.json"),
    )


class TestRegistry(unittest.TestCase):
    def test_builtin_loaded(self):
        reg = fresh_registry()
        self.assertGreater(len(reg.all()), 25)
        self.assertIsNotNone(reg.get("phishing.dmarc_fail"))

    def test_weight_from_config(self):
        reg = fresh_registry()
        # вес берётся из config.yaml: phishing.weights.dmarc_fail = 35
        self.assertEqual(reg.weight("phishing.dmarc_fail"), 35)

    def test_disable_zeroes_weight(self):
        reg = fresh_registry()
        reg.set_enabled("phishing.dmarc_fail", False)
        self.assertFalse(reg.enabled("phishing.dmarc_fail"))
        self.assertEqual(reg.weight("phishing.dmarc_fail"), 0)

    def test_state_persists(self):
        d = tempfile.mkdtemp()
        decl = os.path.join(d, "rules.yaml")
        state = os.path.join(d, "state.json")
        reg = RuleRegistry(CONFIG, declarative_path=decl, state_path=state)
        reg.set_enabled("account.bruteforce", False)
        # новый реестр читает состояние с диска
        reg2 = RuleRegistry(CONFIG, declarative_path=decl, state_path=state)
        self.assertFalse(reg2.enabled("account.bruteforce"))

    def test_add_declarative(self):
        d = tempfile.mkdtemp()
        decl = os.path.join(d, "rules.yaml")
        reg = RuleRegistry(CONFIG, declarative_path=decl,
                           state_path=os.path.join(d, "state.json"))
        reg.add_declarative(Rule(
            id="custom.test", name="Тест", description="d",
            category="phishing", default_weight=22, weight=22,
            source="declarative", rtype="keyword", field_scope="both",
            patterns=["лотерея"],
        ))
        self.assertIn("custom.test", [r.id for r in reg.declarative()])
        # перезагрузка с диска
        reg2 = RuleRegistry(CONFIG, declarative_path=decl,
                            state_path=os.path.join(d, "state.json"))
        self.assertIsNotNone(reg2.get("custom.test"))
        self.assertEqual(reg2.weight("custom.test"), 22)


if __name__ == "__main__":
    unittest.main()
