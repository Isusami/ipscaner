#!/usr/bin/env python3
"""
Functional tests for ip_scanner.py
Uses well-known public IPs guaranteed to respond to ICMP.
"""

import sys
import os
import io
import tempfile
import importlib.util
import unittest

# ── Load ip_scanner as a module (without running main) ───────────────────────
spec = importlib.util.spec_from_file_location(
    "ip_scanner", os.path.join(os.path.dirname(__file__), "ip_scanner.py")
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


# Known always-up public IPs (Cloudflare DNS, Google DNS)
ALIVE_IPS = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"]
# TEST-NET reserved range — must never respond
DEAD_IPS  = ["192.0.2.1", "192.0.2.2", "198.51.100.1", "203.0.113.1"]


class TestPingFallback(unittest.TestCase):
    """subprocess ping() helper."""

    def test_known_alive(self):
        for ip in ALIVE_IPS[:2]:
            with self.subTest(ip=ip):
                self.assertTrue(mod.ping(ip, count=1), f"{ip} should be reachable")

    def test_known_dead(self):
        for ip in DEAD_IPS[:2]:
            with self.subTest(ip=ip):
                self.assertFalse(mod.ping(ip, count=1), f"{ip} should NOT be reachable")


class TestFastIcmpScanner(unittest.TestCase):
    """Raw ICMP scanner (fast_scan_icmp)."""

    def _scan(self, hosts, **kw):
        buf    = io.StringIO()
        result = mod.fast_scan_icmp(hosts, rate=500, timeout=2.0, out_fh=buf, **kw)
        if result is None:
            self.skipTest("Raw ICMP socket unavailable (need root/admin)")
        return result, buf

    def test_finds_cloudflare_dns(self):
        result, _ = self._scan(["1.1.1.1", "1.0.0.1", "192.0.2.1", "192.0.2.2"])
        found = set(result)
        self.assertIn("1.1.1.1",    found)
        self.assertIn("1.0.0.1",    found)
        self.assertNotIn("192.0.2.1", found)

    def test_output_file_written(self):
        result, buf = self._scan(["8.8.8.8", "192.0.2.1"])
        if result:
            written = buf.getvalue().strip().splitlines()
            self.assertIn("8.8.8.8", written)

    def test_no_duplicates(self):
        result, _ = self._scan(["1.1.1.1", "1.1.1.1", "192.0.2.1"])
        self.assertEqual(len(result), len(set(result)))

    def test_result_sorted(self):
        result, _ = self._scan(["1.0.0.1", "1.1.1.1", "192.0.2.1"])
        import ipaddress
        self.assertEqual(result, sorted(result, key=ipaddress.IPv4Address))


class TestInterleave(unittest.TestCase):
    """_interleave() helper."""

    def _make_ranges(self, *cidrs):
        ranges = []
        seen   = set()
        mod._add_tokens(list(cidrs), ranges, seen)
        return ranges

    def test_all_ips_present(self):
        ranges = self._make_ranges("10.0.0.1-3", "10.0.1.1-3")
        result = mod._interleave(ranges)
        self.assertEqual(sorted(result), sorted(
            ["10.0.0.1", "10.0.0.2", "10.0.0.3",
             "10.0.1.1", "10.0.1.2", "10.0.1.3"]
        ))

    def test_interleave_no_duplicates(self):
        ranges = self._make_ranges("10.0.0.1-5", "10.0.0.1-5")
        result = mod._interleave(ranges)
        self.assertEqual(len(result), len(set(result)))

    def test_covers_both_ranges_early(self):
        """First N elements should contain IPs from both ranges (round-robin)."""
        ranges = self._make_ranges("10.0.0.1-100", "10.0.1.1-100")
        result = mod._interleave(ranges)
        first_10 = set(result[:10])
        has_first  = any(ip.startswith("10.0.0.") for ip in first_10)
        has_second = any(ip.startswith("10.0.1.") for ip in first_10)
        self.assertTrue(has_first  and has_second,
                        "Round-robin should mix both ranges in early results")


class TestOutputAppend(unittest.TestCase):
    """Output file must always append, never overwrite."""

    def test_append_across_scans(self):
        hosts = ["1.1.1.1", "192.0.2.1"]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            fname = f.name

        try:
            # Two sequential scans — both should append
            for _ in range(2):
                fh = open(fname, "a")
                result = mod.fast_scan_icmp(hosts, rate=500, timeout=2.0, out_fh=fh)
                fh.close()
                if result is None:
                    self.skipTest("Raw ICMP socket unavailable")

            with open(fname) as f:
                lines = [l.strip() for l in f if l.strip()]

            # 1.1.1.1 should appear in both passes (at least 2 occurrences)
            count = lines.count("1.1.1.1")
            self.assertGreaterEqual(count, 2,
                "1.1.1.1 should appear at least once per pass when appending")
        finally:
            os.unlink(fname)


class TestPresets(unittest.TestCase):
    """Built-in CF preset integrity."""

    def test_cf_preset_count(self):
        cidrs = mod._load_preset("cf")
        self.assertGreater(len(cidrs), 900)

    def test_cf_preset_known_ranges(self):
        cidrs = set(mod._PRESETS["cf"]["cidrs"])
        self.assertTrue(any("1.1.1" in c for c in cidrs))
        self.assertTrue(any("104.16" in c for c in cidrs))


class TestParsing(unittest.TestCase):
    """IP range parsing."""

    def _parse(self, token):
        ranges = []
        seen   = set()
        mod._add_tokens([token], ranges, seen)
        return [ip for hosts, _ in ranges for ip in hosts]

    def test_cidr_24(self):
        ips = self._parse("192.168.1.0/24")
        self.assertEqual(len(ips), 254)
        self.assertIn("192.168.1.1",   ips)
        self.assertIn("192.168.1.254", ips)

    def test_cidr_32(self):
        ips = self._parse("1.2.3.4/32")
        self.assertEqual(ips, ["1.2.3.4"])

    def test_dash_notation(self):
        ips = self._parse("10.0.0.1-5")
        self.assertEqual(ips, ["10.0.0.1", "10.0.0.2", "10.0.0.3",
                                "10.0.0.4", "10.0.0.5"])

    def test_base_range(self):
        ips = self._parse("10.0.0 1 3")
        self.assertEqual(ips, ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    def test_dedup_across_calls(self):
        ranges = []
        seen   = set()
        mod._add_tokens(["192.168.1.0/30"], ranges, seen)
        mod._add_tokens(["192.168.1.0/30"], ranges, seen)  # duplicate
        total = sum(len(h) for h, _ in ranges)
        self.assertEqual(total, 2)

    def test_invalid_token_skipped(self):
        ranges = []
        seen   = set()
        mod._add_tokens(["not_an_ip"], ranges, seen)
        self.assertEqual(ranges, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
