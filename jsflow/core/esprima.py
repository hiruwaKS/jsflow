"""
This module is used to parse JavaScript code into an Abstract Syntax Tree (AST) using Esprima.
It is used in the opgen module to generate the object property graph.
"""

import os
import subprocess
import re

main_js_path = os.path.realpath(
    os.path.join(os.path.dirname(__file__), "../../esprima-csv/main.js")
)
search_js_path = os.path.realpath(
    os.path.join(os.path.dirname(__file__), "../../esprima-csv/search.js")
)


def esprima_parse(path="-", args=[], input=None, print_func=print):
    # use "universal_newlines" instead of "text" if you're using Python <3.7
    #        ↓ ignore this error if your editor shows
    proc = subprocess.Popen(
        ["node", main_js_path, path] + args,
        text=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = proc.communicate(input)
    print_func(stderr)
    return stdout


def esprima_search(module_name, search_path, print_func=print):
    proc = subprocess.Popen(
        ["node", search_js_path, module_name, search_path],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = proc.communicate()
    print_func(stderr)
    main_path, module_path = stdout.split("\n")[:2]
    return main_path, module_path


def get_file_list(module_name):
    script = "var main_func=require('{}');".format(module_name)
    # use "universal_newlines" instead of "text" if you're using Python <3.7
    #        ↓ ignore this error if your editor shows
    proc = subprocess.Popen(
        ["node", main_js_path, "-", "-o", "-"],
        text=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = proc.communicate(script)
    file_list = []
    for line in stderr.splitlines():
        # Strip ANSI color codes and surrounding markers.
        clean = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
        if clean.startswith("["):
            clean = clean[1:].strip()
        if clean.endswith("]"):
            clean = clean[:-1].strip()
        if clean.startswith("Analyzing "):
            file_path = clean[len("Analyzing ") :].strip()
            if file_path != "stdin":
                file_list.append(file_path)
    return file_list
