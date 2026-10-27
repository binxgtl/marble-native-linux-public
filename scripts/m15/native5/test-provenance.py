#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
import tempfile
import unittest
from pathlib import Path
from provenance import inventory, ROLES

class Tests(unittest.TestCase):
    def test_exact_local_bytes_no_promotion(self):
        with tempfile.TemporaryDirectory() as d:
            paths = {}
            for role in ROLES:
                p = Path(d)/role
                p.write_bytes(('synthetic-'+role).encode())
                paths[role] = p
            a = inventory(paths)
            self.assertEqual(a, inventory(paths))
            self.assertFalse(a['candidate_ready'])
            self.assertFalse(a['comparison_eligible'])
            paths['observer'].write_bytes(b'different-native-observer')
            self.assertNotEqual(a['files']['observer'], inventory(paths)['files']['observer'])
            del paths['kernel']
            with self.assertRaises(ValueError): inventory(paths)

    def test_missing_and_empty_reject(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'empty'
            paths = dict.fromkeys(ROLES, p)
            with self.assertRaises(ValueError): inventory(paths)
            p.touch()
            with self.assertRaises(ValueError): inventory(paths)

if __name__ == '__main__': unittest.main()
