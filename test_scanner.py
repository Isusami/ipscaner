#!/usr/bin/env python3
"""
Functional tests for ip_scanner.py
Uses well-known public IPs guaranteed to respond to ICMP.
"""

import sys
import os
import io
import time
import importlib.util
import unittest

# ── Load ip_scanner as a module (without running main) ───────────────────────
spec = importlib.util.spec_from_file_location("ip_scanner", os.path.join(os.path.dirname(__file__), "ip_scanner.py"))
mod  = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


# Known always-up public IPs (Cloudflare DNS, Google DNS, OpenDNS)
ALIVE_IPS = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "208.67.222.222"]
# IPs in TEST-NET reserved range — should never respond
DEAD_IPS  = ["192.0.2.1", "192.0.2.2", "198.51.100.1", "203.0.113.1"]


class TestPingFallback(unittest.TestCase):
    """Test the subprocess ping() helper."""

    def test_known_alive(self):
        for ip in ALIVE_IPS[:2]:  # only 2 to keep it fast
            with self.subTest(ip=ip):
                self.assertTrue(mod.ping(ip, count=1), f"{ip} should be reachable")

    def test_known_dead(self):
        for ip in DEAD_IPS[:2]:
            with self.subTest(ip=ip):
                self.assertFalse(mod.ping(ip, count=1), f"{ip} should NOT be reachable")


class TestFastIcmpScanner(unittest.TestCase):
    """Test the raw ICMP scanner (fast_scan_icmp)."""

    def test_finds_cloudflare_dns(self):
        """1.1.1.1 and 1.0.0.1 must be found."""
        hosts = ["1.1.1.1", "1.0.0.1", "192.0.2.1", "192.0.2.2"]
        buf   = io.StringIO()

        result = mod.fast_scan_icmp(hosts, rate=500, timeout=2.0, out_fh=buf)

        if result is None:
            self.skipTest("Raw ICMP socket unavailable on this system (need root/admin)")

        found = set(result)
        self.assertIn("1.1.1.1", found,  "1.1.1.1 (Cloudflare DNS) must respond")
        self.assertIn("1.0.0.1", found,  "1.0.0.1 (Cloudflare DNS) must respond")
        self.assertNotIn("192.0.2.1", found, "TEST-NET IP must NOT respond")

    def test_output_file_written(self):
        """Alive IPs must be written to the output file handle immediately."""
        hosts = ["8.8.8.8", "192.0.2.1"]
        buf   = io.StringIO()

        result = mod.fast_scan_icmp(hosts, rate=500, timeout=2.0, out_fh=buf)

        if result is None:
            self.skipTest("Raw ICMP socket unavailable on this system (need root/admin)")

        written = buf.getvalue().strip().splitlines()
        if result:
            self.assertTrue(len(written) >= 1, "At least one IP should be in output file")
            self.assertIn("8.8.8.8", written, "8.8.8.8 should be in output file")

    def test_no_duplicates(self):
        """Same IP listed twice should only appear once in results."""
        hosts = ["1.1.1.1", "1.1.1.1", "192.0.2.1"]
        buf   = io.StringIO()

        result = mod.fast_scan_icmp(hosts, rate=500, timeout=2.0, out_fh=buf)

        if result is None:
            self.skipTest("Raw ICMP socket unavailable on this system (need root/admin)")

        self.assertEqual(len(result), len(set(result)), "No duplicate IPs in result")


class TestPresets(unittest.TestCase):
    """Test built-in CF preset is intact."""

    def test_cf_preset_loaded(self):
        cidrs = mod._load_preset("cf")
        self.assertGreater(len(cidrs), 900, "CF preset should have 900+ collapsed ranges")

    def test_cf_preset_includes_known_ranges(self):
        cidrs = set(mod._PRESETS["cf"]["cidrs"])
        self.assertTrue(any("1.1.1" in c for c in cidrs), "Should include 1.1.1.x range")
        self.assertTrue(any("104.16" in c for c in cidrs), "Should include 104.16.x.x range")


class TestParsing(unittest.TestCase):
    """Test IP range parsing."""

    def _parse(self, token):
        ranges = []
        seen   = set()
        mod._add_tokens([token], ranges, seen)
        return [ip for hosts, _ in ranges for ip in hosts]

    def test_cidr_24(self):
        ips = self._parse("192.168.1.0/24")
        self.assertEqual(len(ips), 254)
        self.assertIn("192.168.1.1", ips)
        self.assertIn("192.168.1.254", ips)

    def test_dash_notation(self):
        ips = self._parse("10.0.0.1-5")
        self.assertEqual(ips, ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"])

    def test_base_range(self):
        ips = self._parse("10.0.0 1 3")
        self.assertEqual(ips, ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    def test_dedup(self):
        ranges = []
        seen   = set()
        mod._add_tokens(["192.168.1.0/30"], ranges, seen)
        mod._add_tokens(["192.168.1.0/30"], ranges, seen)   # duplicate
        total = sum(len(h) for h, _ in ranges)
        self.assertEqual(total, 2, "Duplicate CIDR should not add hosts twice")


if __name__ == "__main__":
    unittest.main(verbosity=2)
