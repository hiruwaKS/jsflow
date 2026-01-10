class FakeGraph:
    def __init__(
        self,
        new_trace_rule,
        node_attrs=None,
        edge_attrs=None,
        file_paths=None,
        name_map=None,
        parent_edges=None,
        child_nodes=None,
    ):
        self.new_trace_rule = new_trace_rule
        self.node_attrs = node_attrs or {}
        self.edge_attrs = edge_attrs or {}
        self.file_paths = file_paths or {}
        self.name_map = name_map or {}
        self.parent_edges = parent_edges or {}
        self.child_nodes = child_nodes or {}

    def get_node_attr(self, node):
        return self.node_attrs.get(node, {})

    def get_in_edges(self, node, edge_type=None):
        return self.parent_edges.get(node, [])

    def get_name_from_child(self, node, order=None):
        return self.name_map.get(node)

    def get_node_file_path(self, node):
        return self.file_paths.get(node)

    def get_edge_attr(self, u, v):
        return self.edge_attrs.get((u, v), {})

    def get_all_child_nodes(self, node):
        return self.child_nodes.get(node, [])
