import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from analyze_overlap import package_key


class PackageIdentityTests(unittest.TestCase):
    def test_python_names_normalize(self):
        self.assertEqual(package_key('pkg:pypi/My_Package@1.0', 'unused', '1.0'),
                         ('pypi', 'my-package', '1.0'))

    def test_binary_packages_remain_separate(self):
        self.assertNotEqual(package_key('pkg:deb/debian/libc6@2.36', '', '2.36'),
                            package_key('pkg:deb/debian/libc-bin@2.36', '', '2.36'))

    def test_versions_remain_separate(self):
        self.assertNotEqual(package_key('pkg:pypi/flask@2.2.2', '', '2.2.2'),
                            package_key('pkg:pypi/flask@3.1.3', '', '3.1.3'))


if __name__ == '__main__':
    unittest.main()
