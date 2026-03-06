import subprocess
import time
import unittest
from unittest.mock import MagicMock, patch, Mock
import os
import concurrent.futures

from jsflow.core import esprima

class TestEsprimaOnDataset(unittest.TestCase):
    '''it will run plain esprima (which generate ast instead of csv) on all js files in the dataset, and check if there are any parsing errors.'''

    def test_esprima_parsing_on_dataset(self):
        # return
        '''this takes a while'''
        wrapper_path = "esprima-csv/esprima_wrapper.js"
        dataset_path = "evaluation/explodejs-datasets/secbench-dataset/"
        
        js_files = [os.path.join(root, file) 
            for root, dirs, files in os.walk(dataset_path) 
            for file in files if file.endswith(".js") and os.path.basename(root) == "src"]
        print(f"Found {len(js_files)} JavaScript files in the dataset.")
        
        failed_files = []
        
        def process_file(file):
            process = subprocess.Popen(
                ["node", wrapper_path, file],
                text=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            _, stderr = process.communicate()
            if stderr:
                return (file, stderr)
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            results = executor.map(process_file, js_files)
            
            for result in results:
                if result:
                    failed_files.append(result)
        
        if failed_files:
            error_message = f"\nTotal parsing errors: {len(failed_files)}/{len(js_files)} files\n"
            for file, stderr in failed_files[:5]:
                error_message += f"\n{file}:\n{stderr[:200]}...\n"
            self.fail(error_message)
    
class TestEsprimaParse(unittest.TestCase):
    @patch('subprocess.Popen')
    def test_esprima_parse_basic(self, mock_popen):
        mock_proc = Mock()
        mock_proc.communicate.return_value = ("output", "")
        mock_popen.return_value = mock_proc
        
        result = esprima.esprima_parse("test.js")
        self.assertEqual(result, "output")
        
        mock_popen.assert_called_once()
        args = mock_popen.call_args[0][0]
        self.assertEqual(args[0], "node")
        self.assertTrue("test.js" in args)

    @patch('subprocess.Popen')
    def test_esprima_parse_with_args(self, mock_popen):
        mock_proc = Mock()
        mock_proc.communicate.return_value = ("output", "")
        mock_popen.return_value = mock_proc
        
        result = esprima.esprima_parse("test.js", args=["--option1", "--option2"])
        self.assertEqual(result, "output")
        
        args = mock_popen.call_args[0][0]
        self.assertEqual(args[0], "node")
        self.assertIn("--option1", args)
        self.assertIn("--option2", args)

    @patch('subprocess.Popen')
    def test_esprima_parse_with_input(self, mock_popen):
        mock_proc = Mock()
        mock_proc.communicate.return_value = ("output", "")
        mock_popen.return_value = mock_proc
        
        input_code = "const x = 1;"
        result = esprima.esprima_parse("-", input=input_code)
        self.assertEqual(result, "output")
        
        mock_popen.assert_called_once()
        args = mock_popen.call_args[0][0]
        self.assertEqual(args[2], "-")

    # @patch('subprocess.Popen')
    # def test_esprima_parse_stderr_handling(self, mock_popen):
    #     mock_proc = Mock()
    #     mock_proc.communicate.return_value = ("output", "error message")
    #     mock_popen.return_value = mock_proc
        
    #     print_func = Mock()
    #     result = esprima.esprima_parse("test.js", print_func=print_func)
        
    #     self.assertEqual(result, "output")
    #     print_func.assert_called_once_with("error message")

    @patch('subprocess.Popen')
    def test_esprima_search(self, mock_popen):
        mock_proc = Mock()
        mock_proc.communicate.return_value = ("/path/to/main.js\n/path/to/module.js\n", "")
        mock_popen.return_value = mock_proc
        
        main_path, module_path = esprima.esprima_search("express", "/path/to/search")
        
        self.assertEqual(main_path, "/path/to/main.js")
        self.assertEqual(module_path, "/path/to/module.js")

    @patch('subprocess.Popen')
    def test_esprima_search_with_print_func(self, mock_popen):
        mock_proc = Mock()
        mock_proc.communicate.return_value = ("/main.js\n/module.js\n", "search error")
        mock_popen.return_value = mock_proc
        
        print_func = Mock()
        main_path, module_path = esprima.esprima_search(
            "module", "/path", print_func=print_func
        )
        
        print_func.assert_called_once_with("search error")

    @patch('subprocess.Popen')
    def test_get_file_list(self, mock_popen):
        stderr_output = """
        [\x1b[32mAnalyzing /path/to/file1.js\x1b[0m
        [\x1b[32mAnalyzing /path/to/file2.js\x1b[0m
        [\x1b[32mAnalyzing stdin\x1b[0m
        [\x1b[32mAnalyzing /path/to/file3.js\x1b[0m
        """
        mock_proc = Mock()
        mock_proc.communicate.return_value = ("", stderr_output)
        mock_popen.return_value = mock_proc
        
        result = esprima.get_file_list("module_name")
        
        self.assertEqual(len(result), 3)
        self.assertIn("/path/to/file1.js", result)
        self.assertIn("/path/to/file2.js", result)
        self.assertIn("/path/to/file3.js", result)
        self.assertNotIn("stdin", result)

    @patch('subprocess.Popen')
    def test_get_file_list_empty(self, mock_popen):
        mock_proc = Mock()
        mock_proc.communicate.return_value = ("", "")
        mock_popen.return_value = mock_proc
        
        result = esprima.get_file_list("module_name")
        
        self.assertEqual(result, [])

    @patch('subprocess.Popen')
    def test_get_file_list_only_stdin(self, mock_popen):
        stderr_output = "[\x1b[32mAnalyzing stdin\x1b[0m"
        mock_proc = Mock()
        mock_proc.communicate.return_value = ("", stderr_output)
        mock_popen.return_value = mock_proc
        
        result = esprima.get_file_list("module_name")
        
        self.assertEqual(result, [])

    @patch('subprocess.Popen')
    def test_get_file_list_with_node_colors(self, mock_popen):
        stderr_output = """
        [\u001b[36mAnalyzing /path/to/file1.js\u001b[0m
        [\u001b[36mAnalyzing /path/to/file2.js\u001b[0m
        """
        mock_proc = Mock()
        mock_proc.communicate.return_value = ("", stderr_output)
        mock_popen.return_value = mock_proc
        
        result = esprima.get_file_list("module_name")
        
        self.assertEqual(len(result), 2)
        self.assertIn("/path/to/file1.js", result)
        self.assertIn("/path/to/file2.js", result)


class TestEsprimaPaths(unittest.TestCase):
    def test_main_js_path_exists(self):
        self.assertTrue(os.path.exists(esprima.main_js_path))

    def test_search_js_path_exists(self):
        self.assertTrue(os.path.exists(esprima.search_js_path))


if __name__ == "__main__":
    unittest.main()
