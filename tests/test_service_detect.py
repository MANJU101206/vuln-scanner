import unittest

from vuln_scanner.service_detect import guess_os_hint, identify_service


class TestServiceDetect(unittest.TestCase):
    def test_identifies_openssh_from_ssh_banner(self):
        fp = identify_service("SSH-2.0-OpenSSH_7.4")
        self.assertEqual(fp.product, "OpenSSH")
        self.assertEqual(fp.version, "7.4")

    def test_identifies_apache_from_header_hint(self):
        fp = identify_service("HTTP/1.1 200 OK", header_hints={"Server": "Apache/2.4.49 (Unix)"})
        self.assertEqual(fp.product, "Apache")
        self.assertEqual(fp.version, "2.4.49")

    def test_identifies_nginx_from_header_hint(self):
        fp = identify_service("", header_hints={"Server": "nginx/1.18.0"})
        self.assertEqual(fp.product, "nginx")
        self.assertEqual(fp.version, "1.18.0")

    def test_identifies_vsftpd_backdoor_version(self):
        fp = identify_service("220 (vsFTPd 2.3.4)")
        self.assertEqual(fp.product, "vsftpd")
        self.assertEqual(fp.version, "2.3.4")

    def test_unknown_banner_returns_no_product(self):
        fp = identify_service("some totally unrecognized banner text")
        self.assertIsNone(fp.product)

    def test_display_name_formats_product_and_version(self):
        fp = identify_service("SSH-2.0-OpenSSH_8.9")
        self.assertEqual(fp.display_name, "OpenSSH 8.9")

    def test_guess_os_hint_from_apache_banner(self):
        self.assertEqual(guess_os_hint("Apache/2.4.41 (Ubuntu)"), "Ubuntu")

    def test_guess_os_hint_returns_none_when_absent(self):
        self.assertIsNone(guess_os_hint("Apache/2.4.41"))


if __name__ == "__main__":
    unittest.main()
