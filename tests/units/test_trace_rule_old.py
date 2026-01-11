import unittest

from jsflow.core.trace_rule import TraceRule
from tests.units.vul_checking_fakes import FakeGraph


class TestTraceRuleOld(unittest.TestCase):
    def test_trace_rule_old_exist_start_end(self):
        node_attrs = {
            10: {"type": "AST_CALL"},
            11: {"type": "AST_METHOD_CALL"},
        }
        child_nodes = {1: [10], 2: [11]}
        name_map = {10: "foo", 11: "bar"}
        graph = FakeGraph(
            new_trace_rule=False,
            node_attrs=node_attrs,
            child_nodes=child_nodes,
            name_map=name_map,
        )
        path = [1, 2]

        self.assertTrue(TraceRule("start_with_func", ["foo"], graph).check(path))
        self.assertTrue(TraceRule("end_with_func", ["bar"], graph).check(path))
        self.assertTrue(TraceRule("exist_func", ["bar"], graph).check(path))

    def test_trace_rule_old_not_exist(self):
        node_attrs = {
            10: {"type": "AST_CALL"},
        }
        child_nodes = {1: [10]}
        name_map = {10: "parseInt"}
        graph = FakeGraph(
            new_trace_rule=False,
            node_attrs=node_attrs,
            child_nodes=child_nodes,
            name_map=name_map,
        )
        path = [1]

        self.assertFalse(TraceRule("not_exist_func", ["parseInt"], graph).check(path))


if __name__ == "__main__":
    unittest.main()
