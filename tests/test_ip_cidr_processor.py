import os
import sys
import tempfile
import types
import unittest


class Dummy:
    def __init__(self, *args, **kwargs):
        pass

    def __call__(self, *args, **kwargs):
        return Dummy()

    def __getattr__(self, name):
        return Dummy()


def make_module(name):
    module = types.ModuleType(name)
    module.__getattr__ = lambda attr: Dummy
    return module


yaml = types.ModuleType('yaml')
yaml.safe_load = lambda stream: None
yaml.dump = lambda *args, **kwargs: None
sys.modules.setdefault('yaml', yaml)
sys.modules.setdefault('psutil', make_module('psutil'))
sys.modules.setdefault('requests', make_module('requests'))

tk = make_module('tkinter')
tk.END = 'end'
ttk = make_module('tkinter.ttk')
filedialog = make_module('tkinter.filedialog')
messagebox = make_module('tkinter.messagebox')
simpledialog = make_module('tkinter.simpledialog')
tk.ttk = ttk
tk.filedialog = filedialog
tk.messagebox = messagebox
tk.simpledialog = simpledialog
sys.modules.setdefault('tkinter', tk)
sys.modules.setdefault('tkinter.ttk', ttk)
sys.modules.setdefault('tkinter.filedialog', filedialog)
sys.modules.setdefault('tkinter.messagebox', messagebox)
sys.modules.setdefault('tkinter.simpledialog', simpledialog)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(ROOT, 'src'))

from ip_cidr_processor import IPCIDRProcessor, IPCIDRProcessorGUI


class FakeTk:
    def splitlist(self, data):
        return data if isinstance(data, tuple) else tuple(str(data).split())


class FakeRoot:
    def __init__(self):
        self.tk = FakeTk()


class FakeListbox:
    def __init__(self):
        self.items = []
        self.bg = 'white'

    def config(self, **kwargs):
        if 'bg' in kwargs:
            self.bg = kwargs['bg']

    def get(self, start, end):
        return tuple(self.items)

    def insert(self, index, value):
        self.items.append(value)


class FakeDropEvent:
    def __init__(self, data):
        self.data = data
        self.action = 'copy'


class IPCIDRProcessorTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.previous_cwd = os.getcwd()
        os.chdir(self.temp_dir.name)
        self.processor = IPCIDRProcessor()

    def tearDown(self):
        os.chdir(self.previous_cwd)
        self.temp_dir.cleanup()

    def test_extracts_compressed_ipv6(self):
        self.assertEqual(self.processor.extract_ips('2001:db8::1 ::1'), ['2001:db8::1', '::1'])

    def test_rejects_invalid_prefix_lengths(self):
        self.assertEqual(self.processor.extract_ips('192.168.1.1/99 2001:db8::/129'), [])

    def test_extracts_ipv4_from_url_with_port(self):
        text = 'source=http://192.168.1.1:8080/list.txt backup=https://10.0.0.5/path'
        self.assertEqual(self.processor.extract_ips(text), ['192.168.1.1', '10.0.0.5'])

    def test_ipv4_mapped_ipv6_is_not_double_counted(self):
        self.assertEqual(self.processor.extract_ips('allow ::ffff:192.0.2.128'), ['::ffff:c000:280'])

    def test_extracts_precisely_from_garbage_text(self):
        text = (
            'bad 999.1.1.1 abc192.168.1.2def '
            'valid=8.8.8.8, cidr=10.0.0.5/24 '
            'range 192.168.1.1-192.168.1.3 '
            'ipv6 [2001:db8::1]:443 ::1'
        )
        result = set(self.processor.process_input_to_ips(text))
        self.assertEqual(result, {
            '8.8.8.8/32',
            '10.0.0.0/24',
            '192.168.1.1/32',
            '192.168.1.2/31',
            '2001:db8::1/128',
            '::1/128',
        })

    def test_range_endpoints_are_not_counted_twice(self):
        result = sorted(self.processor.process_input_to_ips('192.168.1.1 - 192.168.1.3'))
        self.assertEqual(result, ['192.168.1.1/32', '192.168.1.2/31'])

    def test_ipv6_ranges_convert_to_cidr(self):
        result = sorted(self.processor.process_input_to_ips('2001:db8::1 - 2001:db8::3'))
        self.assertEqual(result, ['2001:db8::1/128', '2001:db8::2/127'])

    def test_aggressive_optimization_does_not_expand_coverage(self):
        result = self.processor.optimize_cidr_list(['10.0.0.0/25', '10.0.1.0/25'], aggressive=True)
        self.assertEqual(result, ['10.0.0.0/25', '10.0.1.0/25'])

    def test_adjacent_networks_still_collapse(self):
        result = self.processor.optimize_cidr_list(['10.0.0.0/25', '10.0.0.128/25'], aggressive=True)
        self.assertEqual(result, ['10.0.0.0/24'])

    def test_normal_and_aggressive_optimization_keep_exact_coverage(self):
        cidrs = ['10.0.0.0/25', '10.0.0.128/25', '10.0.2.0/25', '2001:db8::/127', '2001:db8::2/127']
        expected = ['10.0.0.0/24', '10.0.2.0/25', '2001:db8::/126']
        self.assertEqual(self.processor.optimize_cidr_list(cidrs, aggressive=False), expected)
        self.assertEqual(self.processor.optimize_cidr_list(cidrs, aggressive=True), expected)

    def test_url_validation_uses_real_host_parsing(self):
        gui = object.__new__(IPCIDRProcessorGUI)
        self.assertTrue(gui.validate_url('https://example.technology/path'))
        self.assertTrue(gui.validate_url('https://[2001:db8::1]/list.txt'))
        self.assertFalse(gui.validate_url('https://999.999.999.999/list.txt'))
        self.assertFalse(gui.validate_url('https://bad_host.example/list.txt'))
        self.assertFalse(gui.validate_url('ftp://example.com/list.txt'))

    def test_drag_and_drop_adds_supported_files_from_files_and_directories(self):
        gui = object.__new__(IPCIDRProcessorGUI)
        gui.root = FakeRoot()
        listbox = FakeListbox()
        with tempfile.TemporaryDirectory() as folder:
            txt_file = os.path.join(folder, 'input.TXT')
            ignored_file = os.path.join(folder, 'image.png')
            nested = os.path.join(folder, 'nested')
            os.mkdir(nested)
            log_file = os.path.join(nested, 'events.log')
            for path in (txt_file, ignored_file, log_file):
                with open(path, 'w', encoding='utf-8') as handle:
                    handle.write('192.168.1.1')

            gui._on_drop(FakeDropEvent((txt_file, ignored_file, folder)), listbox, 'files')

        self.assertEqual(listbox.items, [txt_file, log_file])

    def test_drag_and_drop_validates_urls(self):
        gui = object.__new__(IPCIDRProcessorGUI)
        gui.root = FakeRoot()
        listbox = FakeListbox()

        gui._on_drop(FakeDropEvent((
            'https://example.com/list.txt',
            'ftp://example.com/list.txt',
            'https://999.999.999.999/list.txt',
            'https://example.com/list.txt',
        )), listbox, 'urls')

        self.assertEqual(listbox.items, ['https://example.com/list.txt'])


if __name__ == '__main__':
    unittest.main()
