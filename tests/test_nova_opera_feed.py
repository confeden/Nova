import unittest

from nova_opera_feed import endpoints_for_country, parse_endpoint_feed, valid_endpoint


class OperaEndpointFeedTest(unittest.TestCase):
    def test_feed_cannot_supply_local_credentials_or_malformed_endpoints(self):
        for value in ("127.0.0.1:443", "10.1.2.3:443", "user:secret@example.com:443",
                      "example.com:0", "example.com:70000", "example.com:443/path", "[::1]:443"):
            self.assertFalse(valid_endpoint(value), value)
        self.assertTrue(valid_endpoint("[2606:4700:4700::1111]:443"))
        self.assertTrue(valid_endpoint("proxy.opera.com:443"))
    def test_parses_regions_and_maps_us_to_am(self):
        body = '{"regions": {"EU": ["1.2.3.4:443"], "US": ["5.6.7.8:443"], "as": ["9.9.9.9:443"]}}'
        parsed = parse_endpoint_feed(body)
        self.assertEqual(parsed, {"EU": ["1.2.3.4:443"], "AM": ["5.6.7.8:443"], "AS": ["9.9.9.9:443"]})

    def test_drops_unknown_regions_and_bad_entries(self):
        body = '{"regions": {"XX": ["1.2.3.4:443"], "EU": ["nocolon", "", "1.2.3.4:443", "1.2.3.4:443"]}}'
        self.assertEqual(parse_endpoint_feed(body), {"EU": ["1.2.3.4:443"]})

    def test_junk_gives_empty(self):
        self.assertEqual(parse_endpoint_feed("not json"), {})
        self.assertEqual(parse_endpoint_feed('{"regions": []}'), {})
        self.assertEqual(parse_endpoint_feed(None), {})

    def test_endpoints_for_country(self):
        feed = {"AS": ["9.9.9.9:443"]}
        self.assertEqual(endpoints_for_country(feed, "AS"), ["9.9.9.9:443"])
        self.assertEqual(endpoints_for_country(feed, "EU"), [])
        self.assertEqual(endpoints_for_country({}, "AM"), [])


if __name__ == "__main__":
    unittest.main()
