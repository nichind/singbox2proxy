import unittest
from singbox2proxy import SingBoxCore


class TestSingBoxCore(unittest.TestCase):
    def test_ensure_core(self):
        core = SingBoxCore()
        self.assertTrue(core._ensure_executable())


if __name__ == "__main__":
    unittest.main()
