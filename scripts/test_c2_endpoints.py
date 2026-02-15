
import unittest
import requests
import json
import time

class TestHTTPDecoy(unittest.TestCase):
    BASE_URL = "http://localhost:8888"

    def test_cobalt_strike_beacon(self):
        """Test Cobalt Strike beacon endpoint"""
        try:
            resp = requests.get(f"{self.BASE_URL}/beacon")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.text, "")
        except requests.exceptions.ConnectionError:
            self.fail("Could not connect to HTTP decoy")

    def test_meterpreter(self):
        """Test Meterpreter endpoint"""
        try:
            resp = requests.get(f"{self.BASE_URL}/meterpreter")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.content, b'\x00\x00\x00\x00')
        except requests.exceptions.ConnectionError:
            self.fail("Could not connect to HTTP decoy")

    def test_rat_registration(self):
        """Test RAT registration endpoint"""
        try:
            resp = requests.post(f"{self.BASE_URL}/rat/register")
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertTrue(data['registered'])
            self.assertTrue(len(data['id']) > 0)
        except requests.exceptions.ConnectionError:
            self.fail("Could not connect to HTTP decoy")

if __name__ == '__main__':
    # Wait for container to start
    time.sleep(2)
    unittest.main()
