import unittest
import ast
import sys
import os

class TestParsePortsFromArgs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Read the file
        try:
            with open('nova.pyw', 'r', encoding='utf-8') as f:
                source = f.read()
        except FileNotFoundError:
             # Fallback if running from inside tests/
             try:
                 with open('../nova.pyw', 'r', encoding='utf-8') as f:
                    source = f.read()
             except FileNotFoundError:
                 # Try to find it relative to the test file location
                 base_dir = os.path.dirname(os.path.abspath(__file__))
                 repo_root = os.path.dirname(base_dir)
                 nova_path = os.path.join(repo_root, 'nova.pyw')
                 with open(nova_path, 'r', encoding='utf-8') as f:
                    source = f.read()

        # Parse the AST
        tree = ast.parse(source)

        # Find the function definition
        function_def = None
        # The function is nested inside a try block, so we need to traverse
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == 'parse_ports_from_args':
                function_def = node
                break

        if not function_def:
            raise ValueError("Could not find parse_ports_from_args function definition")

        # Compile the function
        # We need to wrap it in a Module to compile it
        module = ast.Module(body=[function_def], type_ignores=[])
        # Add line numbers (required for compilation)
        ast.fix_missing_locations(module)

        # Execute the function definition to bring it into existence
        code = compile(module, filename='<ast>', mode='exec')
        namespace = {}
        exec(code, namespace)

        cls.parse_ports_from_args = staticmethod(namespace['parse_ports_from_args'])

    def test_basic_tcp_port(self):
        args = ["--filter-tcp=80"]
        tcp, udp = self.parse_ports_from_args(args)
        self.assertEqual(tcp, {"tcp.DstPort == 80"})
        self.assertEqual(udp, set())

    def test_basic_udp_port(self):
        args = ["--filter-udp=53"]
        tcp, udp = self.parse_ports_from_args(args)
        self.assertEqual(tcp, set())
        self.assertEqual(udp, {"udp.DstPort == 53"})

    def test_multiple_ports(self):
        args = ["--filter-tcp=80,443"]
        tcp, udp = self.parse_ports_from_args(args)
        self.assertEqual(tcp, {"tcp.DstPort == 80", "tcp.DstPort == 443"})
        self.assertEqual(udp, set())

    def test_port_range(self):
        args = ["--filter-tcp=1000-2000"]
        tcp, udp = self.parse_ports_from_args(args)
        self.assertEqual(tcp, {"(tcp.DstPort >= 1000 and tcp.DstPort <= 2000)"})
        self.assertEqual(udp, set())

    def test_mixed_ports_and_ranges(self):
        args = ["--filter-tcp=80,1000-2000,443"]
        tcp, udp = self.parse_ports_from_args(args)
        expected_tcp = {
            "tcp.DstPort == 80",
            "(tcp.DstPort >= 1000 and tcp.DstPort <= 2000)",
            "tcp.DstPort == 443"
        }
        self.assertEqual(tcp, expected_tcp)
        self.assertEqual(udp, set())

    def test_dict_input(self):
        args = {"args": ["--filter-tcp=80"]}
        tcp, udp = self.parse_ports_from_args(args)
        self.assertEqual(tcp, {"tcp.DstPort == 80"})
        self.assertEqual(udp, set())

    def test_invalid_input_type(self):
        tcp, udp = self.parse_ports_from_args(123)
        self.assertEqual(tcp, set())
        self.assertEqual(udp, set())

        tcp, udp = self.parse_ports_from_args(None)
        self.assertEqual(tcp, set())
        self.assertEqual(udp, set())

    def test_malformed_range(self):
        # Should be handled by try-except pass
        args = ["--filter-tcp=1000-"]
        # With "1000-", split('-') returns ['1000', '']
        # The code does `f"(tcp.DstPort >= {start} and tcp.DstPort <= {end})"`
        # So expected is `(tcp.DstPort >= 1000 and tcp.DstPort <= )`
        # This is technically what the code produces currently.
        # However, testing exact buggy output might not be ideal, but verifies current behavior.
        # Wait, if start/end are strings, it just interpolates them.
        tcp, udp = self.parse_ports_from_args(args)
        self.assertIn("(tcp.DstPort >= 1000 and tcp.DstPort <= )", tcp)

    def test_wf_prefix(self):
        args = ["--wf-tcp=80", "--wf-udp=53"]
        tcp, udp = self.parse_ports_from_args(args)
        self.assertEqual(tcp, {"tcp.DstPort == 80"})
        self.assertEqual(udp, {"udp.DstPort == 53"})

    def test_args_cleaning(self):
        args = ["  --filter-tcp=80  "]
        tcp, udp = self.parse_ports_from_args(args)
        self.assertEqual(tcp, {"tcp.DstPort == 80"})

    def test_non_string_args(self):
         args = [123, None, "--filter-tcp=80"]
         tcp, udp = self.parse_ports_from_args(args)
         self.assertEqual(tcp, {"tcp.DstPort == 80"})

if __name__ == '__main__':
    unittest.main()
