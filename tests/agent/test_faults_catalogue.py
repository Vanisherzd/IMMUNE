import ast
import importlib
import os
import pathlib
import re
import sys
import unittest


SCRIPTS = pathlib.Path(__file__).resolve().parents[2] / "scripts"


def assignment_value(tree, name):
    return next(
        node.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
    )


def catalogue():
    tree = ast.parse((SCRIPTS / "faults.py").read_text())
    cases = assignment_value(tree, "CASES")
    return tree, {
        ast.literal_eval(key): {
            keyword.arg: ast.literal_eval(keyword.value)
            for keyword in value.keywords
        }
        for key, value in zip(cases.keys, cases.values)
    }


def tool_names():
    tree = ast.parse((SCRIPTS / "agent.py").read_text())
    tools = assignment_value(tree, "TOOLS")
    return {ast.literal_eval(item)["name"] for item in tools.elts}


class FaultCatalogueTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tree, cls.cases = catalogue()
        cls.tools = tool_names()

    def test_inject_branches_match_catalogue(self):
        inject = next(
            node for node in self.tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "inject"
        )
        branch = next(node for node in inject.body if isinstance(node, ast.If))
        injected = set()
        while True:
            comparison = branch.test
            self.assertIsInstance(comparison, ast.Compare)
            self.assertIsInstance(comparison.left, ast.Name)
            self.assertEqual(comparison.left.id, "case")
            self.assertEqual(len(comparison.ops), 1)
            self.assertIsInstance(comparison.ops[0], ast.Eq)
            self.assertEqual(len(comparison.comparators), 1)
            value = comparison.comparators[0]
            self.assertIsInstance(value, ast.Constant)
            self.assertIsInstance(value.value, str)
            injected.add(value.value)
            if len(branch.orelse) != 1 or not isinstance(branch.orelse[0], ast.If):
                break
            branch = branch.orelse[0]

        catalogue_names = set(self.cases)
        message = (
            f"missing inject branches: {catalogue_names - injected}; "
            f"uncatalogued inject branches: {injected - catalogue_names}"
        )
        self.assertEqual(injected, catalogue_names, message)

    def test_catalogue_metadata_is_valid(self):
        tiers = {entry["tier"] for entry in self.cases.values()}
        for tier in tiers:
            self.assertIsInstance(tier, str)
            self.assertTrue(tier)

        for name, entry in self.cases.items():
            with self.subTest(case=name):
                self.assertIs(type(entry["min_actions"]), int)
                self.assertGreaterEqual(entry["min_actions"], 1)
                self.assertIsInstance(entry["fix_tools"], set)
                self.assertTrue(entry["fix_tools"])
                self.assertLessEqual(entry["fix_tools"], self.tools)
                re.compile(entry["cause"])
                self.assertIn(entry["tier"], tiers)
                if "diag_tools" in entry:
                    self.assertLessEqual(entry["diag_tools"], self.tools)


if __name__ == "__main__":
    unittest.main()
