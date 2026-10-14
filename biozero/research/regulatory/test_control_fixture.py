# SPDX-License-Identifier: AGPL-3.0-only
"""Control acquisition boundaries; no network/model/biology evidence."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import control_fixture as control


class ControlBoundaryTests(unittest.TestCase):
    def test_existing_outputs_never_overwritten_or_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / 'source'
            file.write_bytes(b'original')
            with self.assertRaises(ValueError):
                control.immutable_write(file, b'new')
            self.assertEqual(file.read_bytes(), b'original')
            link = Path(tmp) / 'alias'
            link.symlink_to(file)
            with self.assertRaises(ValueError):
                control.immutable_write(link, b'new')
            fifo = Path(tmp) / 'fifo'
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, 'not_regular'):
                control.bounded_regular_read(fifo, 100)
            oversized = Path(tmp) / 'oversized'
            oversized.write_bytes(b'x' * 101)
            with self.assertRaisesRegex(ValueError, 'size_limit'):
                control.bounded_regular_read(oversized, 100)

    def test_cache_absence_requires_explicit_network_authorization(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(control.urllib.request, 'build_opener') as opener:
            with self.assertRaisesRegex(ValueError, 'explicit_fetch_required'):
                control.prepare(tmp)
            opener.assert_not_called()

    def test_redirect_never_creates_a_followup_request(self):
        self.assertIsNone(control.NoRedirect().redirect_request(None, None, 302, 'Found', {}, 'https://other.example/'))


if __name__ == '__main__':
    unittest.main()
