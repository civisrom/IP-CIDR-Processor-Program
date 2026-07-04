import os
import sys
import tempfile
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_ROOT = os.path.join(REPO_ROOT, 'src')
sys.path.insert(0, SRC_ROOT)

from ip_cidr_processor import IPCIDRProcessor, SUPPORTED_DROP_EXTENSIONS  # noqa: E402


class ProcessorTestCase(unittest.TestCase):
    def setUp(self):
        self._old_cwd = os.getcwd()
        self._tmpdir = tempfile.TemporaryDirectory()
        os.chdir(self._tmpdir.name)
        self.processor = IPCIDRProcessor()

    def tearDown(self):
        os.chdir(self._old_cwd)
        self._tmpdir.cleanup()


class IPExtractionTests(ProcessorTestCase):
    def test_json_ipv4_prefix_priority_ignores_other_ips(self):
        text = (
            '{"probe": "10.8.3.1", "prefixes": ['
            '{"ipv4Prefix": "91.205.157.0/24"},'
            '{"ipv4Prefix": "91.205.216.0/22"},'
            '{"ipv4Prefix": "193.107.112.0/22"},'
            '{"ipv4Prefix": "195.18.16.0/22"}'
            '], "nextHop": "193.233.231.208"}'
        )

        report = self.processor.build_processing_report(
            text,
            include_ipv4=True,
            include_ipv6=False,
            optimize=False,
        )

        self.assertEqual(
            report['final_cidrs'],
            ['91.205.157.0/24', '91.205.216.0/22', '193.107.112.0/22', '195.18.16.0/22'],
        )
        self.assertEqual(
            self.processor.apply_mask(report['final_cidrs'], 'keenetic-webadmin-udp-41495'),
            'access-list _WEBADMIN_GigabitEthernet1\n'
            '    permit udp 91.205.157.0 255.255.255.0 0.0.0.0 0.0.0.0 port eq 41495\n'
            '    permit description winmobile\n'
            '    permit udp 91.205.216.0 255.255.252.0 0.0.0.0 0.0.0.0 port eq 41495\n'
            '    permit description winmobile\n'
            '    permit udp 193.107.112.0 255.255.252.0 0.0.0.0 0.0.0.0 port eq 41495\n'
            '    permit description winmobile\n'
            '    permit udp 195.18.16.0 255.255.252.0 0.0.0.0 0.0.0.0 port eq 41495\n'
            '    permit description winmobile\n'
            '    deny udp 0.0.0.0 0.0.0.0 0.0.0.0 0.0.0.0 port eq 443',
        )

    def test_smart_extraction_from_garbage_text(self):
        text = (
            'url=http://192.168.1.1:8080 '
            'ipv6=[2001:db8::1] '
            'bad=999.1.1.1 '
            'release=1.2.3.4-alpha '
            'file=backup_10.0.0.1.txt'
        )

        self.assertEqual(
            self.processor.extract_ips(text),
            ['192.168.1.1', '2001:db8::1'],
        )

    def test_ranges_are_not_double_counted(self):
        self.assertEqual(
            self.processor.build_processing_report('192.168.1.1-192.168.1.3')['final_cidrs'],
            ['192.168.1.1/32', '192.168.1.2/31'],
        )

    def test_suspicious_report_does_not_flag_dates_uuid_or_semver_as_ranges(self):
        text = 'date=2024-01-01 uuid=550e8400-e29b-41d4-a716-446655440000 version=1.2.3.4-alpha'

        self.assertEqual(self.processor.get_suspicious_tokens(text), [])

    def test_sort_places_more_specific_network_first_for_same_address(self):
        self.assertEqual(
            self.processor.sort_ip_addresses(['10.0.0.0/24', '10.0.0.0/25']),
            ['10.0.0.0/25', '10.0.0.0/24'],
        )

    def test_json_files_are_supported_for_drag_and_drop(self):
        self.assertIn('.json', SUPPORTED_DROP_EXTENSIONS)
        self.assertIn('.yaml', SUPPORTED_DROP_EXTENSIONS)

    def test_old_keenetic_mask_config_is_upgraded(self):
        old_config = {
            'masks': [
                {'name': 'default', 'prefix': '', 'suffix': '', 'separator': '\n'},
                {
                    'name': 'keenetic-webadmin-udp-41495',
                    'category': 'Router',
                    'prefix': '',
                    'suffix': '',
                    'separator': '\n',
                    'header': 'access-list _WEBADMIN_GigabitEthernet1',
                    'line_template': '    permit udp {network} {netmask} 0.0.0.0 0.0.0.0 port eq 41495',
                    'ip_version': 4,
                },
            ],
            'default_mask': 'default',
        }

        normalized = self.processor._normalize_config(old_config)
        keenetic = next(mask for mask in normalized['masks'] if mask['name'] == 'keenetic-webadmin-udp-41495')

        self.assertEqual(
            keenetic['line_template'],
            '    permit udp {network} {netmask} 0.0.0.0 0.0.0.0 port eq 41495\n'
            '    permit description winmobile',
        )
        self.assertEqual(
            keenetic['footer'],
            '    deny udp 0.0.0.0 0.0.0.0 0.0.0.0 0.0.0.0 port eq 443',
        )

    def test_interrupted_keenetic_example_template_is_upgraded(self):
        old_config = {
            'masks': [
                {'name': 'default', 'prefix': '', 'suffix': '', 'separator': '\n'},
                {
                    'name': 'keenetic-webadmin-udp-41495',
                    'category': 'Router',
                    'prefix': '',
                    'suffix': '',
                    'separator': '\n',
                    'header': 'access-list _WEBADMIN_GigabitEthernet1',
                    'line_template': (
                        '    permit udp {network} {netmask} 0.0.0.0 0.0.0.0 port eq 41495\n'
                        '    permit description example'
                    ),
                    'footer': '    deny udp 0.0.0.0 0.0.0.0 0.0.0.0 0.0.0.0 port eq 443',
                    'ip_version': 4,
                },
            ],
            'default_mask': 'default',
        }

        normalized = self.processor._normalize_config(old_config)
        keenetic = next(mask for mask in normalized['masks'] if mask['name'] == 'keenetic-webadmin-udp-41495')

        self.assertEqual(
            keenetic['line_template'],
            '    permit udp {network} {netmask} 0.0.0.0 0.0.0.0 port eq 41495\n'
            '    permit description winmobile',
        )
        self.assertEqual(
            keenetic['footer'],
            '    deny udp 0.0.0.0 0.0.0.0 0.0.0.0 0.0.0.0 port eq 443',
        )

    def test_mask_template_variables_allow_firewall_ports_and_description(self):
        added = self.processor.add_mask(
            'keenetic-custom-firewall',
            '',
            '',
            '\n',
            'Router',
            'Custom Keenetic firewall rule',
            line_template=(
                '    permit {protocol} {network} {netmask} 0.0.0.0 0.0.0.0 port eq {permit_port}\n'
                '    permit description {rule_description}'
            ),
            header='access-list _WEBADMIN_GigabitEthernet1',
            footer='    deny {protocol} 0.0.0.0 0.0.0.0 0.0.0.0 0.0.0.0 port eq {deny_port}',
            ip_version=4,
            variables={
                'protocol': 'tcp',
                'permit_port': '8443',
                'deny_port': '9443',
                'rule_description': 'office-admin',
            },
        )

        self.assertTrue(added)
        self.assertEqual(
            self.processor.apply_mask(['203.0.113.0/24'], 'keenetic-custom-firewall'),
            'access-list _WEBADMIN_GigabitEthernet1\n'
            '    permit tcp 203.0.113.0 255.255.255.0 0.0.0.0 0.0.0.0 port eq 8443\n'
            '    permit description office-admin\n'
            '    deny tcp 0.0.0.0 0.0.0.0 0.0.0.0 0.0.0.0 port eq 9443',
        )


if __name__ == '__main__':
    unittest.main()
