"""
This module is used to check the vulnerabilities of the code.
"""

from .trace_rule import TraceRule
from .vul_func_lists import *


def get_path_text(G, path, caller):
    """
    get the code by ast number
    Args:
        G: the graph
        path: the path with ast nodes
    Return:
        str: a string with text path
    """
    res_path = ""
    cur_path_str1 = ""
    cur_path_str2 = ""
    for node in path:
        cur_node_attr = G.get_node_attr(node)
        if cur_node_attr.get("lineno:int") is None:
            continue
        if cur_node_attr.get("labels:label") in ["Artificial", "Artificial_AST"]:
            continue
        # if cur_node_attr.get('lineno:int') == '': # workaround?
        #     G.logger.error('No line number for node {} {}'.format(node, cur_node_attr))
        #     continue
        cur_path_str1 += cur_node_attr["lineno:int"] + "->"
        start_lineno = int(cur_node_attr["lineno:int"])
        end_lineno = int(cur_node_attr["endlineno:int"] or start_lineno)
        content = None
        try:
            content = G.get_node_file_content(node)
        except:
            pass
        if content is not None:
            for l in range(start_lineno, end_lineno + 1):
                if "function" in content[l]:
                    content = (
                        "".join(content[start_lineno : l + 1]).rstrip()
                        + " ... (omitted)\n"
                    )
                    break
            if type(content) is list:
                content = "".join(content[start_lineno : end_lineno + 1])
            cur_path_str2 += "{}\t{}".format(start_lineno, content)
    cur_path_str1 += G.get_node_attr(caller).get("lineno:int", "?")
    G.logger.debug(cur_path_str1)

    res_path += "==========================\n"
    res_path += "{}\n".format(G.get_node_file_path(path[0]))
    res_path += cur_path_str2
    return res_path


def traceback(G, vul_type, start_node=None):
    """
    traceback from the leak point, the edge is OBJ_REACHES
    Args:
        G: the graph
        vul_type: the type of vulernability, listed below

    Return:
        the paths include the objs,
        the string description of paths,
        the list of callers,
    """

    def find_func_name(node):
        func = G.get_node_attr(node).get("funcid:int")
        if not func:
            while G.get_node_attr(node).get("type") not in [
                "AST_FUNC_DECL",
                "AST_CLOSURE",
                "AST_METHOD",
                "AST_TOPLEVEL",
            ]:
                node = G.get_in_edges(node, edge_type="PARENT_OF")[0][0]
            func = node
        # print('found node', node, 'in function', func, G.get_name_from_child(func))
        return G.get_name_from_child(func)

    res_path = ""
    expoit_func_list = signature_lists[vul_type]

    if G.new_trace_rule:
        func_nodes = G.get_node_by_attr("type", "DUMMY_STMT")
        # print('func nodes', func_nodes)
    else:
        func_nodes = G.get_node_by_attr("type", "AST_METHOD_CALL")
        func_nodes += G.get_node_by_attr("type", "AST_CALL")
        func_nodes += G.get_node_by_attr("type", "AST_NEW")
    ret_pathes = []
    caller_list = []
    for func_node in func_nodes:
        # we assume only one obj_decl edge
        if G.new_trace_rule:
            func_name = find_func_name(func_node)
        else:
            func_name = G.get_name_from_child(func_node, order=1)
        if func_name in expoit_func_list:
            caller = func_node
            caller = G.find_nearest_upper_CPG_node(caller)
            caller_list.append("{} called {}".format(caller, func_name))
            pathes = G._dfs_upper_by_edge_type(caller, "OBJ_REACHES")

            # here we treat the single calling as a possible path
            # pathes.append([caller])
            G.logger.debug("Paths:")

            # give the end node one more chance, find the parent obj of the ending point
            """
            for path in pathes:
                last_node = path[-1]
                upper_nodes = G._dfs_upper_by_edge_type(last_node, 
                        "OBJ_TO_PROP")
                for uppernode in upper_nodes:
                    path.append(uppernode)
                #print('--', upper_nodes)
            """
            for path in pathes:
                ret_pathes.append(path)
                path.reverse()
                res_path += get_path_text(G, path, caller)
    return ret_pathes, res_path, caller_list


def do_vul_checking(G, rule_list, pathes):
    """
    Check paths against a list of trace rules to identify vulnerabilities.

    This function applies a list of trace rules to candidate paths. A path
    is considered vulnerable if it satisfies ALL rules in the rule_list.
    Each rule is a tuple of (rule_function_name, rule_arguments).

    The function works by:
    1. Creating TraceRule objects for each rule in the rule_list
    2. For each candidate path, checking all rules in sequence
    3. If any rule fails, the path is rejected
    4. Only paths that pass all rules are returned

    Common rule types:
    - 'has_user_input': Checks if path contains tainted user input
    - 'not_exist_func': Checks that specified functions don't appear in path
    - 'exist_func': Checks that specified functions appear in path
    - 'end_with_func': Checks that path ends at a specific function call
    - 'start_with_func': Checks that path starts at a specific function
    - 'start_within_file': Checks that path starts in a specific file
    - 'not_start_within_file': Checks that path doesn't start in specific files

    Args:
        G (Graph): The graph object containing the analysis results
        rule_list (list): List of rule tuples. Each tuple contains:
            - rule_function_name (str): Name of the trace rule function.
              Must match a method name in TraceRule class.
            - rule_arguments: Arguments for the rule function. Can be:
              - None: No arguments needed
              - list: List of function names, file names, or variable names
              - Other types as required by specific rules
        pathes (list): List of candidate paths to check. Each path is a
            list of node IDs representing an execution path through the graph.

    Returns:
        list: List of paths that satisfy all rules in rule_list. Each path
            is a list of node IDs. Empty list if no paths satisfy all rules.

    Example:
        >>> # Check for OS command injection: user input reaching exec without sanitization
        >>> rule_list = [
        ...     ('has_user_input', None),  # Path must contain user input
        ...     ('not_exist_func', ['parseInt']),  # No parseInt sanitization
        ...     ('end_with_func', ['sink_hqbpillvul_exec'])  # Ends at exec()
        ... ]
        >>> vulnerable = do_vul_checking(G, rule_list, candidate_paths)
        >>> # Check for XSS: user input reaching HTTP write without sanitization
        >>> xss_rules = [
        ...     ('has_user_input', None),
        ...     ('not_exist_func', ['parseInt']),
        ...     ('end_with_func', ['sink_hqbpillvul_http_write'])
        ... ]
        >>> xss_paths = do_vul_checking(G, xss_rules, paths)
    """
    trace_rules = []
    for rule in rule_list:
        trace_rules.append(TraceRule(rule[0], rule[1], G))

    success_pathes = []
    flag = True
    for path in pathes:
        flag = True
        for trace_rule in trace_rules:
            if not trace_rule.check(path):
                flag = False
                break
        if flag:
            success_pathes.append(path)
    return success_pathes


def vul_checking(G, pathes, vul_type):
    """
    Filter paths to identify those that satisfy vulnerability detection rules.

    This function applies vulnerability-specific trace rules to candidate paths
    and returns only those paths that match the vulnerability pattern. Different
    vulnerability types have different rule sets that check for:
    - Presence of user input (source)
    - Absence of sanitization functions
    - Presence of vulnerable sink functions
    - Path characteristics specific to each vulnerability type

    The function uses a rule-based approach where each vulnerability type has
    one or more rule lists. A path is considered vulnerable if it satisfies
    ALL rules in at least one rule list. This allows for multiple patterns
    to be detected for the same vulnerability type.

    Rule evaluation:
    - Rules are applied in order within each rule list
    - All rules in a list must pass for the path to be vulnerable
    - If any rule fails, the next rule list is tried
    - A path is added to results if it satisfies any complete rule list

    Args:
        G (Graph): The graph object containing the analysis results
        pathes (list): List of candidate paths (sequences of node IDs) to check.
            Each path represents a potential data flow from source to sink.
        vul_type (str): Type of vulnerability to check. Must be one of:
            - 'xss': Cross-site scripting - checks for unsanitized user input
              reaching HTTP response writing functions
            - 'os_command': OS command injection - checks for user input reaching
              command execution functions (exec, spawn, etc.)
            - 'code_exec': Code execution vulnerabilities - checks for user input
              reaching eval(), Function(), or command execution
            - 'proto_pollution': Prototype pollution - checks for tainted property
              names being assigned to prototype chains
            - 'path_traversal': Path traversal - checks for URL parameters reaching
              file system operations without sanitization
            - 'nosql': NoSQL injection - checks for user input reaching MongoDB
              query functions without sanitization

    Returns:
        list: List of paths that satisfy the vulnerability detection rules.
            Each path is a list of node IDs representing the vulnerable execution
            path from source to sink. Empty list if no vulnerable paths found.

    Example:
        >>> from jsflow.vul_checking import vul_checking
        >>> # Check for XSS vulnerabilities
        >>> vulnerable_paths = vul_checking(G, candidate_paths, 'xss')
        >>> print(f"Found {len(vulnerable_paths)} XSS vulnerabilities")
        >>> # Check for OS command injection
        >>> cmd_paths = vul_checking(G, paths, 'os_command')
    """
    xss_rule_lists = [
        [
            ("has_user_input", None),
            ("not_start_with_func", ["sink_hqbpillvul_http_write"]),
            ("not_exist_func", ["parseInt"]),
            ("end_with_func", ["sink_hqbpillvul_http_write"]),
        ],
        [
            ("has_user_input", None),
            ("not_start_with_func", ["sink_hqbpillvul_http_setHeader"]),
            ("not_exist_func", ["parseInt"]),
            ("end_with_func", ["sink_hqbpillvul_http_setHeader"]),
        ],
    ]
    os_command_rule_lists = [
        [
            ("has_user_input", None),
            ("not_start_within_file", ["child_process.js"]),
            ("not_exist_func", ["parseInt"]),
        ]
    ]

    code_exec_lists = [
        [
            ("has_user_input", None),
            ("not_start_within_file", ["eval.js"]),
            ("not_exist_func", ["parseInt"]),
        ],
        [
            ("has_user_input", None),
            ("end_with_func", ["Function"]),
            ("not_exist_func", ["parseInt"]),
        ],
        [
            ("has_user_input", None),
            ("end_with_func", ["eval"]),
            ("not_exist_func", ["parseInt"]),
        ],
        # include os command here
        [
            ("has_user_input", None),
            ("not_start_within_file", ["child_process.js"]),
            ("not_exist_func", ["parseInt"]),
        ],
    ]
    proto_pollution = [
        [("has_user_input", None), ("not_exist_func", signature_lists["sanitation"])]
    ]
    path_traversal = [
        [
            ("start_with_var", ["OPGen_TAINTED_VAR_url"]),
            ("not_exist_func", signature_lists["sanitation"]),
            ("end_with_func", signature_lists["path_traversal"]),
            ("exist_func", ["sink_hqbpillvul_fs_read"]),
            # ('exist_func', ['__opgCombine'])
        ],
        [
            ("start_with_var", ["OPGen_TAINTED_VAR_url"]),
            ("not_exist_func", ["parseInt"]),
            ("end_with_func", ["sink_hqbpillvul_http_sendFile"]),
        ],
    ]
    nosql_rule_lists = [
        [
            ("has_user_input", None),
            ("not_start_within_file", ["mongodb.js", "monk.js"]),
            ("not_exist_func", ["parseInt"]),
        ]
    ]

    vul_type_map = {
        "xss": xss_rule_lists,
        "os_command": os_command_rule_lists,
        "code_exec": code_exec_lists,
        "proto_pollution": proto_pollution,
        "path_traversal": path_traversal,
        "nosql": nosql_rule_lists,
    }

    rule_lists = vul_type_map[vul_type]
    success_paths = []
    print("vul_checking", vul_type)
    """
    print(pathes)
    for path in pathes:
        for node in path:
            print(G.get_node_attr(node))
    """
    for rule_list in rule_lists:
        success_paths += do_vul_checking(G, rule_list, pathes)
    # success_paths = list(map(lambda path: G.extend_path_by_cf(path), success_paths))
    print("success: ", success_paths)
    return success_paths


def check_pp(G):
    print("Checking proto_pollution...")

    def _get_children(
        node_id, edge_type=None, child_type=None, child_label=None, edge_scope=None
    ):
        nonlocal G
        children, scopes = [], []
        edges = G.get_out_edges(node_id, edge_type=edge_type)
        for edge in edges:
            aim_node_attr = G.get_node_attr(edge[1])
            aim_edge_scope = edge[-1].get("scope")
            if child_type is not None and aim_node_attr.get("type") != child_type:
                continue
            if (
                child_label is not None
                and aim_node_attr.get("labels:label") != child_label
            ):
                continue
            if edge_scope is not None and aim_edge_scope != edge_scope:
                continue
            children.append(edge[1])
            scopes.append(aim_edge_scope)
        return children, scopes

    results = set()
    for node in G.get_all_nodes():
        # check every assignment
        if G.get_node_attr(node).get("type") != "AST_ASSIGN":
            continue
        children = G.get_ordered_ast_child_nodes(node)
        if len(children) != 2:
            continue
        left, right = children
        # whose left side is prop expression
        if G.get_node_attr(left).get("type") not in ["AST_DIM", "AST_PROP"]:
            continue
        # get all possible scopes
        _, scopes = _get_children(left, edge_type="REFERS_TO", child_label="Name")
        for scope in set(scopes):
            # the left side should have the name nodes of functions in built-in prototypes
            name_nodes, _ = _get_children(
                left, edge_type="REFERS_TO", child_label="Name", edge_scope=scope
            )
            if not (set(name_nodes) & set(G.pollutable_name_nodes)):
                continue
            # make sure the property names are tainted
            prop_children = G.get_ordered_ast_child_nodes(left)
            if len(prop_children) != 2:
                continue
            prop_name_ast_node = prop_children[1]
            prop_name_obj_nodes, _ = _get_children(
                prop_name_ast_node,
                edge_type="REFERS_TO",
                child_label="Object",
                edge_scope=scope,
            )
            if not any(
                map(
                    lambda obj: G.get_node_attr(obj).get("tainted"), prop_name_obj_nodes
                )
            ):
                continue
            # the right side should have tainted objects
            obj_nodes, _ = _get_children(
                right, edge_type="REFERS_TO", child_label="Object", edge_scope=scope
            )
            if not any(map(lambda obj: G.get_node_attr(obj).get("tainted"), obj_nodes)):
                continue
            # if found, add the AST node
            results.add(node)
    if results:
        print("found:", results)
    else:
        print("not found")
    return results
