"""Built-in curated subscription lifecycle and Android connecting-wave parity."""

import json
import math
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import threading
import tkinter as tk

import nova_desktop_ui as desktop
import nova_appearance as appearance
import nova_profiles
import nova_proxy
import nova_subscriptions as subscriptions


class BuiltinListTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.base = self.work.name

    def builtin(self):
        return subscriptions.find(subscriptions.load(self.base), subscriptions.NOVA_LIST_ID)

    def test_builtin_is_injected_into_existing_or_empty_registry_and_cannot_be_removed(self):
        subscriptions.save(self.base, [])
        row = self.builtin()
        self.assertEqual((row['name'], row['interval_hours'], row['enabled'], row['keep']),
                         ('Nova list', 12, True, subscriptions.MAX_NODES))
        with self.assertRaises(ValueError):
            subscriptions.remove(self.base, row['id'])
        subscriptions.save(self.base, [dict(row, name='changed')])
        self.assertEqual(self.builtin(), row)
        subscriptions.set_interval(self.base, row['id'], 24)
        subscriptions.set_enabled(self.base, row['id'], False)
        self.assertEqual((self.builtin()['interval_hours'], self.builtin()['enabled']), (24, False))

    def test_canonical_url_does_not_create_a_second_subscription(self):
        subscriptions.save(self.base, [])
        row, records = subscriptions.add(self.base, subscriptions.NOVA_LIST_URL)
        self.assertEqual(row['id'], subscriptions.NOVA_LIST_ID)
        self.assertEqual(len(records), 1)

    def test_github_folder_spaces_are_encoded_once_on_every_mirror(self):
        mirrors = subscriptions.mirror_urls(subscriptions.NOVA_LIST_URL)
        self.assertEqual(len(mirrors), 3)
        self.assertIn(subscriptions.NOVA_LIST_URL, mirrors)
        self.assertTrue(all('Github%20list/nova-list.json' in url for url in mirrors))
        self.assertFalse(any('%2520' in url for url in mirrors))

    def test_builtin_still_syncs_every_twelve_hours_after_a_fetch_failure(self):
        row = dict(self.builtin(), last_checked_at=1000, fail_streak=4)
        self.assertEqual(subscriptions.due([row], now=1000 + 12 * 3600 - 1), [])
        self.assertEqual(subscriptions.due([row], now=1000 + 12 * 3600), [row])

    def test_curated_refresh_keeps_names_and_empty_snapshot_removes_only_owned_nodes(self):
        node = nova_proxy.ProxyNode(dict(type='socks5', name='SOCKS5_#24_2026nov7', server='example.com', port=1080))
        body = json.dumps(dict(nova_list=dict(version=1, count=1, complete=True), proxies=[node.proxy])).encode()
        fetcher = lambda *a, **kw: subscriptions.FetchResult('ok', body=body)
        with patch.object(nova_proxy, 'parse_many', return_value=([node], {'parsed': 1})):
            outcome, record, _ = subscriptions.refresh(self.base, self.builtin(), fetcher=fetcher)
        self.assertEqual(outcome, 'updated')
        profiles = nova_profiles.list_profiles(self.base)
        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0]['name'], node.name)
        subscriptions.merge_saved(self.base, [record])
        manual = nova_proxy.ProxyNode(dict(type='socks5', name='manual', server='example.net', port=1080))
        nova_profiles.import_candidates(self.base, [nova_proxy.candidate(manual)])
        empty = json.dumps(dict(nova_list=dict(version=1, count=0, complete=True), proxies=[])).encode()
        outcome, _, _ = subscriptions.refresh(self.base, record,
            fetcher=lambda *a, **kw: subscriptions.FetchResult('ok', body=empty))
        self.assertEqual(outcome, 'updated')
        self.assertEqual([p['name'] for p in nova_profiles.list_profiles(self.base)], ['manual'])

    def test_bad_manifest_never_replaces_owned_nodes_or_caches_its_etag(self):
        row = self.builtin()
        for body in (b'<html>error</html>', b'{"nova_list":{"version":1,"count":2},"proxies":[]}'):
            outcome, record, _ = subscriptions.refresh(self.base, row,
                fetcher=lambda *a, **kw: subscriptions.FetchResult('ok', body=body, etag='broken'))
            self.assertEqual(outcome, 'failed')
            self.assertEqual(record['etag'], '')


class AndroidWavesTests(unittest.TestCase):
    def test_trail_mask_has_no_square_corners(self):
        alpha = desktop.connection_waves((560, 420), (280, 169), 1.5, (112, 228, 255)).getchannel('A')
        self.assertEqual(alpha.getpixel((370, 169)), 0)
        self.assertEqual(alpha.getpixel((334, 241)), 0)

    def test_wave_has_a_filled_trail_and_repeats_after_android_cycle(self):
        size, center, elapsed = (560, 420), (280, 169), 1.64
        frame = desktop.connection_waves(size, center, elapsed, (112, 228, 255))
        repeat = desktop.connection_waves(size, center, elapsed + 8.2, (112, 228, 255))
        self.assertEqual(frame.tobytes(), repeat.tobytes())
        reach = math.hypot(280, 251)
        radius = reach * .2
        alpha = frame.getchannel('A')
        front = alpha.getpixel((round(center[0] + radius), center[1]))
        behind = alpha.getpixel((round(center[0] + radius - 12), center[1]))
        inside = alpha.getpixel((round(center[0] + radius - 44), center[1]))
        self.assertGreater(front, behind)
        self.assertGreater(behind, inside)
        self.assertGreater(behind, 10)


class StartupAppearanceTests(unittest.TestCase):
    def test_late_renderer_cannot_overwrite_final_preferences(self):
        with tempfile.TemporaryDirectory() as work:
            scene = object.__new__(desktop.DesktopScene)
            scene.preferences_path = Path(work) / 'appearance.json'
            scene._preferences_lock = threading.Lock()
            scene._saved_generation = -1
            scene._generation = 5
            current = dict(appearance.DEFAULT_PREFERENCES, random_texture_on_start=True)
            scene.flush_preferences(current)
            scene._persist_preferences(4, dict(current, random_texture_on_start=False))
            self.assertTrue(appearance.load_preferences(scene.preferences_path)['random_texture_on_start'])
            scene._persist_preferences(6, dict(current, random_texture_on_start=False))
            self.assertFalse(appearance.load_preferences(scene.preferences_path)['random_texture_on_start'])

    def test_random_setting_applies_on_next_start_not_on_checkbox_toggle(self):
        root = tk.Tk()
        root.withdraw()
        seen = []
        window = desktop.AppearanceWindow(root, appearance.DEFAULT_PREFERENCES, seen.append, show=False)
        try:
            def descendants(widget):
                for child in widget.winfo_children():
                    yield child
                    yield from descendants(child)
            checkbox = next(widget for widget in descendants(window.top)
                            if isinstance(widget, tk.Checkbutton) and widget.cget('text') == 'Случайная фактура при запуске')
            self.assertFalse(window.random_texture.get())
            checkbox.invoke()
            self.assertTrue(seen[-1]['random_texture_on_start'])
            self.assertEqual(seen[-1]['texture'], 'marble')
        finally:
            window.top.destroy()
            root.destroy()

    def test_name_sort_follows_visible_numbers(self):
        records = [dict(name='HTTP_#11_2026nov7', protocol='http'), dict(name='SS_#2_2026nov7', protocol='ss')]
        self.assertEqual([nova_proxy.display_name(r) for r in nova_proxy.sort_records(records, 'name')],
                         ['#2_2026nov7', '#11_2026nov7'])

    def test_owner_defaults_and_opt_in_randomization(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / 'appearance.json'
            prefs = appearance.startup_preferences(path, choose=lambda _: self.fail('disabled by default'))
            self.assertEqual((prefs['theme'], prefs['texture'], prefs['texture_intensity']), ('dnsai', 'marble', .3))
            appearance.save_preferences(path, dict(prefs, random_texture_on_start=True, variant=17))
            seen = []
            def choose(candidates):
                self.assertNotIn('none', candidates)
                previous = appearance.load_preferences(path)['texture']
                self.assertNotIn(previous, candidates)
                seen.append(previous)
                return candidates[0]
            for _ in range(4):
                current = appearance.startup_preferences(path, choose=choose)
                self.assertNotEqual(current['texture'], seen[-1])
                self.assertEqual(current['variant'], 17)
                self.assertEqual(appearance.load_preferences(path), current)


if __name__ == '__main__':
    unittest.main()
