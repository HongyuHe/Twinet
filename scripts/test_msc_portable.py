#!/usr/bin/env python3
"""Regression checks for the portable MSC deployment boundary."""

import contextlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import msc_portable as portable


class PortableTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def manifest(self):
        for name in portable.BUNDLE_FILES:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(name)
        manifest = {"schema_version": 1, "platform": "linux/amd64", "source": {},
                    "sha256": {name: portable.sha256(self.root / name) for name in portable.BUNDLE_FILES}}
        (self.root / "msc_bundle.json").write_text(json.dumps(manifest))
        return manifest

    def test_bundle_checks_every_payload_before_execution(self):
        expected = self.manifest()
        self.assertEqual(portable.verify_bundle(self.root), expected)
        for name in portable.BUNDLE_FILES:
            path = self.root / name
            original = path.read_bytes()
            path.write_bytes(original + b"modified")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                portable.verify_bundle(self.root)
            path.write_bytes(original)

    def test_bundle_rejects_missing_inventory_and_symlinks(self):
        manifest = self.manifest()
        del manifest["sha256"]["bin/twinet"]
        (self.root / "msc_bundle.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "inventory"):
            portable.verify_bundle(self.root)
        self.manifest()
        target = self.root / "bin/twinet"
        target.unlink()
        target.symlink_to(self.root / "docs/13_msc.md")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            portable.verify_bundle(self.root)

    def test_images_require_immutable_digests(self):
        spec = {key: f"example/{key}@sha256:" + "a" * 64 for key in ("image", "router_image", "switch_image")}
        self.assertEqual(len(portable.image_refs(spec)), 3)
        spec["image"] = "example/image:latest"
        with self.assertRaisesRegex(ValueError, "pinned"):
            portable.image_refs(spec)

    def test_collision_detects_native_sidecar(self):
        spec = {"devices": [{"id": "BLACK", "role": "black"}, {"id": "I_A1", "role": "inner"}]}
        names = portable.container_names(spec)
        self.assertEqual(names, {"BLACK", "BLACK-frr", "I_A1"})
        with self.assertRaisesRegex(ValueError, "BLACK-frr"):
            portable.validate_destination(self.root / "app", self.root / "state", self.root / "launcher", names, {"BLACK-frr"})
        self.assertFalse((self.root / "app").exists())

    def test_existing_private_state_and_launcher_are_preserved(self):
        prefix, state, launcher = (self.root / name for name in ("app", "state", "launcher"))
        state.mkdir()
        sentinel = state / "ca-key.pem"
        sentinel.write_text("private fixture remains local")
        with self.assertRaisesRegex(ValueError, "nonempty"):
            portable.validate_destination(prefix, state, launcher, set(), set())
        self.assertEqual(sentinel.read_text(), "private fixture remains local")
        launcher.symlink_to(self.root / "missing")
        with self.assertRaisesRegex(ValueError, "overwrite"):
            portable.validate_destination(prefix, self.root / "fresh-state", launcher, set(), set())

    def test_bundle_has_no_runtime_state_or_keys(self):
        import argparse

        source = self.root / "source"
        for name in portable.BUNDLE_FILES[1:]:
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("public fixture")
        spec = {key: f"example/{key}@sha256:" + "a" * 64 for key in ("image", "router_image", "switch_image")}
        (source / "examples/msc/msc.json").write_text(json.dumps(spec))
        (source / "credentials.txt").write_text("must stay behind")
        (source / "state").mkdir()
        (source / "state/ca-key.pem").write_text("must stay behind")

        def build(root, destination):
            destination.write_text("static binary fixture")
            return {"commit": "test"}

        destination = self.root / "portable.tar.gz"
        with patch.object(portable, "ROOT", source), patch.object(portable, "build_binary", side_effect=build), contextlib.redirect_stdout(io.StringIO()):
            portable.bundle(argparse.Namespace(output=destination))
        with tarfile.open(destination) as archive:
            files = {member.name for member in archive.getmembers() if member.isfile()}
        expected = {"twinet-msc/" + name for name in (*portable.BUNDLE_FILES, "msc_bundle.json")}
        self.assertEqual(files, expected)
        self.assertTrue(destination.with_name(destination.name + ".sha256").exists())

    def test_docker_build_targets_linux_without_writing_source(self):
        root = self.root / "source"
        (root / "cmd").mkdir(parents=True)
        (root / "internal").mkdir()
        (root / "go.mod").write_text("module example\n\ngo 1.25.0\n")
        (root / "go.sum").write_text("")
        destination = self.root / "twinet"
        calls = []

        def docker(*args, **kwargs):
            calls.append(args)
            if args[0] == "run":
                destination.write_text("built")

        with patch.object(portable.shutil, "which", return_value=None), patch.object(portable, "docker", side_effect=docker), patch.object(portable, "output", return_value="sha256:builder"):
            portable.build_binary(root, destination)
        args = calls[1]
        self.assertIn(f"{root}:/src:ro", args)
        self.assertIn("CGO_ENABLED=0", args)
        self.assertIn("GOARCH=amd64", args)
        self.assertEqual(args[-3:], ("-o", "/out/twinet", "./cmd/twinet"))


if __name__ == "__main__":
    unittest.main()
