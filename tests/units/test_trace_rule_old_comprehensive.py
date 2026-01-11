import unittest
from unittest.mock import Mock

from jsflow.core.trace_rule import TraceRuleOld
from tests.units.vul_checking_fakes import FakeGraph


class TestTraceRuleOld(unittest.TestCase):
    def test_exist_func_multiple_in_path(self):
        node_attrs = {
            1: {"type": "AST_CALL"},
            2: {"type": "AST_METHOD_CALL"},
            3: {"type": "AST_CALL"},
        }
        child_nodes = {
            1: [10, 11],
            2: [20, 21],
            3: [30, 31],
        }
        name_map = {
            10: "parseInt",
            11: "parseFloat",
            20: "toString",
            21: "valueOf",
            30: "eval",
            31: "parseInt",
        }
        graph = FakeGraph(
            new_trace_rule=False,
            node_attrs=node_attrs,
            child_nodes=child_nodes,
            name_map=name_map,
        )
        path = [1, 2, 3]

        self.assertTrue(TraceRuleOld("exist_func", ["eval"], graph).check(path))
        self.assertTrue(TraceRuleOld("exist_func", ["parseInt"], graph).check(path))
        self.assertTrue(TraceRuleOld("exist_func", ["toString"], graph).check(path))

    def test_exist_func_none_in_path(self):
        node_attrs = {
            1: {"type": "AST_CALL"},
            2: {"type": "AST_METHOD_CALL"},
        }
        child_nodes = {
            1: [10],
            2: [20],
        }
        name_map = {
            10: "parseInt",
            20: "toString",
        }
        graph = FakeGraph(
            new_trace_rule=False,
            node_attrs=node_attrs,
            child_nodes=child_nodes,
            name_map=name_map,
        )
        path = [1, 2]

        self.assertFalse(TraceRuleOld("exist_func", ["eval"], graph).check(path))

    def test_not_exist_func(self):
        node_attrs = {
            1: {"type": "AST_CALL"},
            2: {"type": "AST_METHOD_CALL"},
        }
        child_nodes = {
            1: [10],
            2: [20],
        }
        name_map = {
            10: "parseInt",
            20: "toString",
        }
        graph = FakeGraph(
            new_trace_rule=False,
            node_attrs=node_attrs,
            child_nodes=child_nodes,
            name_map=name_map,
        )
        path = [1, 2]

        self.assertTrue(TraceRuleOld("not_exist_func", ["eval"], graph).check(path))
        self.assertFalse(TraceRuleOld("not_exist_func", ["parseInt"], graph).check(path))

    def test_start_with_func_matches(self):
        node_attrs = {
            1: {"type": "AST_CALL"},
        }
        child_nodes = {
            1: [10],
        }
        name_map = {
            10: "parseInt",
        }
        graph = FakeGraph(
            new_trace_rule=False,
            node_attrs=node_attrs,
            child_nodes=child_nodes,
            name_map=name_map,
        )
        path = [1]

        self.assertTrue(TraceRuleOld("start_with_func", ["parseInt"], graph).check(path))
        self.assertFalse(TraceRuleOld("start_with_func", ["eval"], graph).check(path))

    def test_start_with_func_nested_calls(self):
        node_attrs = {
            1: {"type": "AST_CALL"},
        }
        child_nodes = {
            1: [10, 11],
        }
        name_map = {
            10: "parseInt",
            11: "eval",
        }
        graph = FakeGraph(
            new_trace_rule=False,
            node_attrs=node_attrs,
            child_nodes=child_nodes,
            name_map=name_map,
        )
        path = [1]

        self.assertTrue(TraceRuleOld("start_with_func", ["eval"], graph).check(path))

    def test_not_start_with_func(self):
        node_attrs = {
            1: {"type": "AST_CALL"},
        }
        child_nodes = {
            1: [10],
        }
        name_map = {
            10: "parseInt",
        }
        graph = FakeGraph(
            new_trace_rule=False,
            node_attrs=node_attrs,
            child_nodes=child_nodes,
            name_map=name_map,
        )
        path = [1]

        self.assertTrue(TraceRuleOld("not_start_with_func", ["eval"], graph).check(path))
        self.assertFalse(TraceRuleOld("not_start_with_func", ["parseInt"], graph).check(path))

    def test_end_with_func(self):
        node_attrs = {
            1: {"type": "AST_CALL"},
            2: {"type": "AST_METHOD_CALL"},
            3: {"type": "AST_CALL"},
        }
        child_nodes = {
            1: [10],
            2: [20],
            3: [30],
        }
        name_map = {
            10: "parseInt",
            20: "toString",
            30: "eval",
        }
        graph = FakeGraph(
            new_trace_rule=False,
            node_attrs=node_attrs,
            child_nodes=child_nodes,
            name_map=name_map,
        )
        path = [1, 2, 3]

        self.assertTrue(TraceRuleOld("end_with_func", ["eval"], graph).check(path))
        self.assertFalse(TraceRuleOld("end_with_func", ["parseInt"], graph).check(path))

    def test_end_with_func_nested_calls(self):
        node_attrs = {
            1: {"type": "AST_CALL"},
        }
        child_nodes = {
            1: [10, 11],
        }
        name_map = {
            10: "parseInt",
            11: "eval",
        }
        graph = FakeGraph(
            new_trace_rule=False,
            node_attrs=node_attrs,
            child_nodes=child_nodes,
            name_map=name_map,
        )
        path = [1]

        self.assertTrue(TraceRuleOld("end_with_func", ["eval"], graph).check(path))

    def test_start_within_file(self):
        node_attrs = {
            1: {},
        }
        graph = FakeGraph(
            new_trace_rule=False,
            node_attrs=node_attrs,
            file_paths={1: "/path/to/app.js"},
        )
        path = [1]

        self.assertTrue(TraceRuleOld("start_within_file", ["app.js"], graph).check(path))
        self.assertFalse(TraceRuleOld("start_within_file", ["other.js"], graph).check(path))

    def test_start_within_file_full_path(self):
        node_attrs = {
            1: {},
        }
        graph = FakeGraph(
            new_trace_rule=False,
            node_attrs=node_attrs,
            file_paths={1: "/path/to/app.js"},
        )
        path = [1]

        self.assertTrue(TraceRuleOld("start_within_file", ["/path/to/app.js"], graph).check(path))

    def test_start_within_file_none_path(self):
        node_attrs = {
            1: {},
        }
        graph = FakeGraph(
            new_trace_rule=False,
            node_attrs=node_attrs,
            file_paths={1: None},
        )
        path = [1]

        self.assertFalse(TraceRuleOld("start_within_file", ["app.js"], graph).check(path))

    def test_not_start_within_file(self):
        node_attrs = {
            1: {},
        }
        graph = FakeGraph(
            new_trace_rule=False,
            node_attrs=node_attrs,
            file_paths={1: "/path/to/app.js"},
        )
        path = [1]

        self.assertTrue(TraceRuleOld("not_start_within_file", ["other.js"], graph).check(path))
        self.assertFalse(TraceRuleOld("not_start_within_file", ["app.js"], graph).check(path))

    def test_has_user_input_from_edges(self):
        node_attrs = {
            1: {},
            2: {},
            300: {"tainted": True},
        }
        edge_attrs = {
            (1, 2): {0: {"type:TYPE": "OBJ_REACHES", "obj": 300}},
        }
        graph = FakeGraph(
            new_trace_rule=False,
            node_attrs=node_attrs,
            edge_attrs=edge_attrs,
        )
        path = [1, 2]

        self.assertTrue(TraceRuleOld("has_user_input", None, graph).check(path))

    def test_has_user_input_no_tainted(self):
        node_attrs = {
            1: {},
            2: {},
            300: {"tainted": False},
        }
        edge_attrs = {
            (1, 2): {0: {"type:TYPE": "OBJ_REACHES", "obj": 300}},
        }
        graph = FakeGraph(
            new_trace_rule=False,
            node_attrs=node_attrs,
            edge_attrs=edge_attrs,
        )
        path = [1, 2]

        self.assertFalse(TraceRuleOld("has_user_input", None, graph).check(path))

    def test_has_user_input_file_fallback(self):
        node_attrs = {
            1: {},
        }
        graph = FakeGraph(
            new_trace_rule=False,
            node_attrs=node_attrs,
            file_paths={1: "/path/to/http.js"},
        )
        path = [1]

        self.assertTrue(TraceRuleOld("has_user_input", None, graph).check(path))

    def test_has_user_input_process_file(self):
        node_attrs = {
            1: {},
        }
        graph = FakeGraph(
            new_trace_rule=False,
            node_attrs=node_attrs,
            file_paths={1: "/path/to/process.js"},
        )
        path = [1]

        self.assertTrue(TraceRuleOld("has_user_input", None, graph).check(path))

    def test_has_user_input_yargs_file(self):
        node_attrs = {
            1: {},
        }
        graph = FakeGraph(
            new_trace_rule=False,
            node_attrs=node_attrs,
            file_paths={1: "/path/to/yargs.js"},
        )
        path = [1]

        self.assertTrue(TraceRuleOld("has_user_input", None, graph).check(path))

    def test_unknown_rule(self):
        node_attrs = {
            1: {},
        }
        graph = FakeGraph(
            new_trace_rule=False,
            node_attrs=node_attrs,
        )
        path = [1]

        self.assertFalse(TraceRuleOld("unknown_rule", None, graph).check(path))


if __name__ == "__main__":
    unittest.main()
