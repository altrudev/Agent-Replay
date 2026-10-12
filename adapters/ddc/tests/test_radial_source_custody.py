"""Security boundary tests: user-selected code cannot execute as an approved DDC adapter."""
from __future__ import annotations
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from agent_replay_ddc import radial_runner as loader


class CustodyTests(unittest.TestCase):
    def test_no_trusted_provisioning_blocks_dynamic_execution(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"src";p.mkdir();source=p/"radial_frequency_v10.py";source.write_bytes(b"raise RuntimeError('would execute')")
            with self.assertRaises(loader.RadialAdapterError):
                loader._verify_radial_source(source,source.read_bytes())

    def test_symlinked_or_mutable_pin_is_not_authority(self):
        with tempfile.TemporaryDirectory() as td:
            pin=Path(td)/"pin";pin.write_text(hashlib.sha256(b"safe").hexdigest())
            source=Path(td)/"module.py";source.write_bytes(b"safe")
            with patch.object(loader,"_TRUST_FILE",pin):
                with self.assertRaises(loader.RadialAdapterError):
                    loader._verify_radial_source(source,source.read_bytes())
            other=Path(td)/"other";other.write_text(pin.read_text());pin.unlink();pin.symlink_to(other)
            with patch.object(loader,"_TRUST_FILE",pin):
                with self.assertRaises(loader.RadialAdapterError):
                    loader._verify_radial_source(source,source.read_bytes())

    def test_digest_change_blocks_without_execution(self):
        with tempfile.TemporaryDirectory() as td:
            pin=Path(td)/"pin";pin.write_text(hashlib.sha256(b"safe").hexdigest())
            source=Path(td)/"module.py";source.write_bytes(b"malicious")
            # Simulate only the enrollment filesystem protection to test
            # the cryptographic comparison, not claim OS identity evidence.
            with patch.object(loader,"_TRUST_FILE",pin), patch.object(loader,"_require_operator_owned",lambda _:None):
                with self.assertRaisesRegex(loader.RadialAdapterError,"differs"):
                    loader._verify_radial_source(source,source.read_bytes())
if __name__=="__main__":unittest.main()
