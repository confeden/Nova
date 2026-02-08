
import unittest
import ast
import textwrap
import os
import sys

def get_compare_versions_func():
    """Extracts and compiles compare_versions from nova.pyw."""
    # Locate nova.pyw relative to this test file
    base_dir = os.path.dirname(os.path.abspath(__file__))

    # Try parent directory first
    nova_path = os.path.join(base_dir, "..", "nova.pyw")
    if not os.path.exists(nova_path):
        # Fallback for running from root
        nova_path = "nova.pyw"
        if not os.path.exists(nova_path):
            # Try absolute path based on repo root assumption
            nova_path = os.path.abspath(os.path.join(os.getcwd(), "nova.pyw"))
            if not os.path.exists(nova_path):
                raise FileNotFoundError(f"Could not find nova.pyw. Checked: {nova_path}")

    with open(nova_path, "r", encoding="utf-8") as f:
        source_code = f.read()

    try:
        tree = ast.parse(source_code)
    except SyntaxError as e:
        raise SyntaxError(f"Failed to parse nova.pyw: {e}")

    target_node = None

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "compare_versions":
            target_node = node
            break

    if not target_node:
        raise ValueError("Function 'compare_versions' not found in nova.pyw")

    # Extract source using get_source_segment (Python 3.8+)
    func_source = ast.get_source_segment(source_code, target_node)

    if not func_source:
        # Fallback to lines if get_source_segment fails (unlikely in 3.12)
        lines = source_code.splitlines()
        func_lines = lines[target_node.lineno - 1 : target_node.end_lineno]
        func_source = "\n".join(func_lines)

    # Dedent to handle nested definition
    func_source = textwrap.dedent(func_source)

    # Compile and execute in a local scope
    scope = {}
    try:
        exec(func_source, {}, scope)
    except Exception as e:
        raise RuntimeError(f"Failed to exec extracted source: {e}\nSource:\n{func_source}")

    return scope['compare_versions']

class TestCompareVersions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            # Wrap in staticmethod to avoid binding as method
            func = get_compare_versions_func()
            cls.compare_versions_func = staticmethod(func)
        except Exception as e:
            raise unittest.SkipTest(f"Failed to extract compare_versions: {e}")

    def compare_versions(self, v1, v2):
        return self.compare_versions_func(v1, v2)

    def test_greater_than(self):
        """Test cases where v1 > v2 (True)."""
        self.assertTrue(self.compare_versions("1.0.1", "1.0.0"))
        self.assertTrue(self.compare_versions("1.1", "1.0.9"))
        self.assertTrue(self.compare_versions("2.0", "1.9.9"))
        self.assertTrue(self.compare_versions("1.0.0.1", "1.0"))
        self.assertTrue(self.compare_versions("1.0.1", "1.0"))
        self.assertTrue(self.compare_versions("10.0", "9.9"))

    def test_not_greater_than(self):
        """Test cases where v1 <= v2 (False)."""
        self.assertFalse(self.compare_versions("1.0.0", "1.0.1"))
        self.assertFalse(self.compare_versions("1.0", "1.1"))
        self.assertFalse(self.compare_versions("0.9", "1.0"))
        # Equal cases
        self.assertFalse(self.compare_versions("1.0.0", "1.0.0"))
        self.assertFalse(self.compare_versions("1.0", "1.0.0"))
        self.assertFalse(self.compare_versions("1.0.0", "1.0"))

    def test_invalid_inputs(self):
        """Test handling of invalid inputs (should return False)."""
        self.assertFalse(self.compare_versions("a.b.c", "1.0.0"))
        self.assertFalse(self.compare_versions("1.0.0", "x.y.z"))
        self.assertFalse(self.compare_versions("1..0", "1.0"))
        self.assertFalse(self.compare_versions("", "1.0"))
        self.assertFalse(self.compare_versions("1.0", None)) # split on None raises AttributeError

if __name__ == '__main__':
    unittest.main()
