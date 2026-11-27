import json
import unittest

import app as cracklab


class CrackLabTests(unittest.TestCase):
    def setUp(self):
        self.client = cracklab.app.test_client()

    def test_index_renders_offline_with_safety_notice_and_breach_example(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        self.assertIn("Educational demo. Do not enter your real passwords.", html)
        self.assertIn("LinkedIn 2012", html)
        self.assertIn("chart.umd.min.js", html)
        self.assertNotIn("cdn.jsdelivr.net", html)
        self.assertNotIn("fonts.googleapis.com", html)

    def test_analyze_edge_cases(self):
        # Empty password
        res = self.client.post("/api/analyze", json={"password": ""})
        self.assertEqual(res.status_code, 400)
        self.assertIn("error", res.get_json())

        # Overly long password
        res = self.client.post("/api/analyze", json={"password": "A" * 300})
        self.assertEqual(res.status_code, 400)
        self.assertIn("error", res.get_json())

        # Invalid payload
        res = self.client.post("/api/analyze", data="not-json", content_type="application/json")
        self.assertEqual(res.status_code, 400)

        # Password exceeding bcrypt's 72-byte limit still works cleanly
        res = self.client.post("/api/analyze", json={"password": "X" * 90})
        self.assertEqual(res.status_code, 200)
        hashes = res.get_json()["hashes"]
        bcrypt_row = next(h for h in hashes if "bcrypt" in h["algorithm"])
        self.assertIn("72 bytes", bcrypt_row.get("note") or "")

    def test_analyze_weak_patterns_and_salts(self):
        # Demo password: password123
        res = self.client.post("/api/analyze", json={"password": "password123"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertLessEqual(data["strength"]["score"], 1)
        self.assertTrue(data["strength"]["in_wordlist"])
        self.assertGreaterEqual(len(data["strength"]["tips"]), 2)

        algos = [h["algorithm"] for h in data["hashes"]]
        self.assertEqual(len(algos), 5)
        for h in data["hashes"]:
            self.assertGreater(h["time_ms"], 0)

        salt_rows = {r["algorithm"]: r for r in data["salt_demo"]["rows"]}
        self.assertTrue(salt_rows["MD5 (Unsalted)"]["identical"])
        self.assertTrue(salt_rows["SHA-256 (Unsalted)"]["identical"])
        self.assertFalse(salt_rows["Argon2id (Auto-Salted)"]["identical"])

        # Keyboard pattern & repeated characters detection
        kbd = self.client.post("/api/analyze", json={"password": "qwerty2024"}).get_json()
        self.assertTrue(any("Keyboard" in r for r in kbd["strength"]["reasons"]))

        rep = self.client.post("/api/analyze", json={"password": "aaaaaa11"}).get_json()
        self.assertTrue(any("Repeated" in r for r in rep["strength"]["reasons"]))

    def test_rainbow_table_hit_and_salted_miss(self):
        res = self.client.post("/api/rainbow-table", json={"password": "password123"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["table_size"], len(cracklab.RAINBOW_TABLE))
        self.assertTrue(data["unsalted"]["found"])
        self.assertEqual(data["unsalted"]["recovered_password"], "password123")
        self.assertFalse(data["salted"]["found"])

    def test_benchmark_real_speed_gap(self):
        res = self.client.post("/api/benchmark", json={"password": "password123"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        by_key = {b["key"]: b for b in data["benchmarks"]}
        self.assertGreater(by_key["md5"]["hashes_per_sec"], by_key["bcrypt"]["hashes_per_sec"] * 100)
        self.assertGreater(by_key["sha256"]["hashes_per_sec"], by_key["argon2"]["hashes_per_sec"] * 100)
        self.assertEqual(len(data["estimates"]["estimates"]), 5)

    def test_crack_battle_stream(self):
        res = self.client.post("/api/crack-battle", json={"password": "password123"})
        self.assertEqual(res.status_code, 200)
        events = [json.loads(line) for line in res.get_data(as_text=True).splitlines() if line.strip()]
        types = [ev["type"] for ev in events]
        self.assertIn("start", types)
        self.assertIn("md5_done", types)
        self.assertIn("bcrypt_done", types)
        self.assertIn("complete", types)

        md5_done = next(ev for ev in events if ev["type"] == "md5_done")
        bcrypt_done = next(ev for ev in events if ev["type"] == "bcrypt_done")
        self.assertTrue(md5_done["found"])
        self.assertFalse(bcrypt_done["found"])
        self.assertTrue(bcrypt_done["stopped_by_time_cap"])
        self.assertGreater(md5_done["hps"], bcrypt_done["hps"] * 100)


if __name__ == "__main__":
    unittest.main(verbosity=2)
