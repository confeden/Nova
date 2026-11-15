"""Version rule, back-off and gate of the background profile issue (Android D45 parity)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "resources"))

import nova_issue_policy as policy
import nova_issuance

H = 3600.0
NOW = 1_800_000_000.0


class VersionRuleTests(unittest.TestCase):
    def test_version_key_orders_numerically(self):
        self.assertLess(policy.version_key("1.9.0"), policy.version_key("1.46.2"))
        self.assertEqual(policy.version_key(""), (0,))

    def test_no_set_issues(self):
        issue, _ = policy.decide({}, policy.KIND_WARP, set_present=False, current_version="1.46.2", now=NOW)
        self.assertTrue(issue)

    def test_unstamped_set_is_renewed_once(self):
        issue, why = policy.decide({}, policy.KIND_WARP, set_present=True, current_version="1.46.2", now=NOW)
        self.assertTrue(issue)
        self.assertIn("без отметки", why)

    def test_stamped_current_or_newer_is_left_alone(self):
        ledger = policy.apply_attempt({}, policy.KIND_WARP, "1.46.2", True, NOW)
        self.assertFalse(policy.decide(ledger, policy.KIND_WARP, set_present=True,
                                       current_version="1.46.2", now=NOW + 99 * H)[0])
        self.assertFalse(policy.decide(ledger, policy.KIND_WARP, set_present=True,
                                       current_version="1.46.1", now=NOW + 99 * H)[0])

    def test_older_stamp_renews_after_update(self):
        ledger = policy.apply_attempt({}, policy.KIND_WARP, "1.46.1", True, NOW)
        self.assertTrue(policy.decide(ledger, policy.KIND_WARP, set_present=True,
                                      current_version="1.46.2", now=NOW + H)[0])

    def test_kinds_are_independent(self):
        ledger = policy.apply_attempt({}, policy.KIND_WARP, "1.46.2", True, NOW)
        self.assertTrue(policy.decide(ledger, policy.KIND_PROTON, set_present=True,
                                      current_version="1.46.2", now=NOW)[0])

    def test_success_after_failures_clears_backoff(self):
        ledger = {}
        for _ in range(3):
            ledger = policy.apply_attempt(ledger, policy.KIND_PROTON, "1.46.2", False, NOW)
        ledger = policy.apply_attempt(ledger, policy.KIND_PROTON, "1.46.2", True, NOW)
        self.assertEqual(ledger["kinds"][policy.KIND_PROTON]["attempts"], 0)


class BackoffTests(unittest.TestCase):
    def _failed(self, times, kind=policy.KIND_WARP):
        ledger = {}
        for _ in range(times):
            ledger = policy.apply_attempt(ledger, kind, "1.46.2", False, NOW)
        return ledger

    def test_schedule_is_1h_3h_12h_daily(self):
        for failures, wait in ((1, H), (2, 3 * H), (3, 12 * H), (4, 24 * H)):
            ledger = self._failed(failures)
            before = policy.decide(ledger, policy.KIND_WARP, set_present=False,
                                   current_version="1.46.2", now=NOW + wait - 60)
            after = policy.decide(ledger, policy.KIND_WARP, set_present=False,
                                  current_version="1.46.2", now=NOW + wait + 60)
            self.assertFalse(before[0], failures)
            self.assertTrue(after[0], failures)

    def test_missing_set_never_gives_up_but_never_faster_than_daily(self):
        ledger = self._failed(9)
        self.assertFalse(policy.decide(ledger, policy.KIND_WARP, set_present=False,
                                       current_version="1.46.2", now=NOW + 23 * H)[0])
        self.assertTrue(policy.decide(ledger, policy.KIND_WARP, set_present=False,
                                      current_version="1.46.2", now=NOW + 25 * H)[0])

    def test_renewal_stops_after_cap(self):
        ledger = self._failed(policy.RENEW_ATTEMPT_CAP)
        issue, why = policy.decide(ledger, policy.KIND_WARP, set_present=True,
                                   current_version="1.46.2", now=NOW + 99 * 24 * H)
        self.assertFalse(issue)
        self.assertIn("вручную", why)

    def test_new_version_resets_the_counter(self):
        ledger = self._failed(policy.RENEW_ATTEMPT_CAP)
        self.assertTrue(policy.decide(ledger, policy.KIND_WARP, set_present=True,
                                      current_version="1.47.0", now=NOW + 99 * 24 * H)[0])


class PersistenceTests(unittest.TestCase):
    def test_roundtrip_and_corrupt_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as base:
            self.assertEqual(policy.load(base), {})
            policy.record_attempt(base, policy.KIND_WARP, "1.46.2", True, NOW)
            self.assertEqual(policy.load(base)["kinds"]["warp"]["issued"], "1.46.2")
            with open(os.path.join(base, "temp", policy.LEDGER_FILENAME), "w", encoding="utf-8") as fh:
                fh.write("{broken")
            self.assertEqual(policy.load(base), {})


class GateTests(unittest.TestCase):
    def test_calm_pc_opens(self):
        self.assertTrue(policy.evaluate_gate(net_rates=[1000, 2000], cpu_busy=[0.1, 0.2],
                                             ac_online=True)[0])

    def test_sustained_traffic_closes_but_a_single_burst_does_not(self):
        busy = policy.GATE_MAX_BYTES_PER_SEC * 3
        self.assertFalse(policy.evaluate_gate(net_rates=[busy, busy])[0])
        self.assertTrue(policy.evaluate_gate(net_rates=[busy, 100])[0])

    def test_cpu_load_closes(self):
        self.assertFalse(policy.evaluate_gate(cpu_busy=[0.95, 0.9])[0])

    def test_battery_rules_apply_only_off_ac(self):
        self.assertFalse(policy.evaluate_gate(ac_online=False, battery_pct=10)[0])
        self.assertFalse(policy.evaluate_gate(ac_online=False, battery_pct=80, battery_saver=True)[0])
        self.assertTrue(policy.evaluate_gate(ac_online=True, battery_pct=10, battery_saver=True)[0])
        self.assertTrue(policy.evaluate_gate(ac_online=None, battery_pct=10)[0])

    def test_unreadable_sensors_do_not_block(self):
        self.assertTrue(policy.evaluate_gate(net_rates=[None, None], cpu_busy=[None])[0])

    def test_check_gate_uses_two_intervals_and_stops_on_request(self):
        ticks = iter(range(0, 100, 3))
        counters = iter([0, 10_000_000, 20_000_000])
        slept = []
        opened, why = policy.check_gate(
            sleep=slept.append, clock=lambda: float(next(ticks)),
            read_net=lambda: next(counters), read_cpu=lambda: (0, 100, 0),
            read_power=lambda: (True, None, False))
        self.assertFalse(opened)
        self.assertIn("канал занят", why)
        self.assertEqual(len(slept), 2)
        opened, why = policy.check_gate(
            should_stop=lambda: True, sleep=lambda s: None, clock=lambda: 0.0,
            read_net=lambda: 0, read_cpu=lambda: None, read_power=lambda: (True, None, False))
        self.assertFalse(opened)


class PlanBackfillVersionTests(unittest.TestCase):
    def _plan(self, ledger, version="1.46.2", present=True, warp_state=None):
        records = []
        if present:
            records = [{"group": "AWG Cloudflare", "valid": True, "origin": "generated", "id": "AWG Cloudflare/WARPgen_01"},
                       {"group": "MASQUE", "valid": True, "id": "MASQUE/m"},
                       {"group": "AWG Proton", "valid": True, "id": "AWG Proton/P1", "endpoint": "1.2.3.4:51820"}]
        account = {"issued_at": NOW - 1000, "nodes_checked_at": NOW - 10, "nodes_source": "github"} if present else None
        steps = nova_issuance.plan_backfill(
            records=records, warp_state=warp_state or {}, proton_account=account,
            stats={"AWG Proton/P1": {"rtt_at": NOW}}, now=NOW, ledger=ledger, app_version=version)
        return [s for s, _ in steps]

    def test_old_behaviour_without_ledger(self):
        self.assertNotIn("warp", self._plan(None))

    def test_unstamped_existing_sets_are_renewed_once(self):
        steps = self._plan({})
        self.assertIn("warp", steps)

    def test_stamped_sets_are_left_alone(self):
        ledger = policy.apply_attempt({}, policy.KIND_WARP, "1.46.2", True, NOW)
        ledger = policy.apply_attempt(ledger, policy.KIND_PROTON, "1.46.2", True, NOW)
        steps = self._plan(ledger)
        self.assertNotIn("warp", steps)
        self.assertNotIn("proton", steps)

    def test_generator_cooldown_still_holds_for_renewal(self):
        steps = self._plan({}, warp_state={"failed_at": NOW - 60})
        self.assertNotIn("warp", steps)


if __name__ == "__main__":
    unittest.main()
