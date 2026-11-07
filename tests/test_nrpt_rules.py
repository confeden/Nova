r"""NRPT: список имён и каскад резолверов.

Список имён задан владельцем целиком (тот, что разблокирует сервис), а не
собран замерами — поэтому здесь пришпилены не отдельные домены, а решения,
которые нельзя потерять при следующей правке списка:

* три имени отданы второй программе владельца (D8) и Nova их не берёт;
* youtube.com ушёл из подмены вместе с переходом на новый список, но маршрут
  YouTube не тронут — он в list/main.txt и остаётся на WARP;
* каскад резолверов идёт в порядке dns-ai → xbox-dns → comss → geohide, и
  строка для PowerShell собирается из него, а не пишется рядом второй копией;
* ветка ai_unlock в PAC отдаёт DIRECT на пересечении ai_unlock и list/second.txt,
  поэтому домен из этого пересечения не имеет права быть в list/main.txt.

`nova.pyw` импортировать нельзя (I15) — константы достаются из AST, как в
`test_relay_env.py` и `test_pac_telegram_priority.py`.
"""

import ast
import io
import os
import unittest
from unittest import mock
import subprocess
import json

import nova_dns_ai


class DnsAiInstallTests(unittest.TestCase):
    def snapshot(self):
        return json.dumps({"interfaces": [{"index": 7, "families": [
            {"family": 2, "servers": ["1.1.1.1"], "static": False},
            {"family": 23, "servers": ["2606:4700:4700::1111"], "static": True}]}],
            "doh": [{"server": server, "exists": False} for server in nova_dns_ai.INSTALL_SERVERS]})

    def test_unsupported_windows_never_changes_dns(self):
        with mock.patch.object(nova_dns_ai, "is_windows_11", return_value=False), \
                mock.patch.object(nova_dns_ai, "_run_dns_setup") as run:
            with self.assertRaisesRegex(RuntimeError, "Windows 11"):
                nova_dns_ai.install_system_dns()
            run.assert_not_called()

    def test_success_verifies_encryption_and_clears_detection_cache(self):
        with mock.patch.object(nova_dns_ai, "is_windows_11", return_value=True), \
                mock.patch.object(nova_dns_ai, "_run_dns_setup", side_effect=[self.snapshot(), "OK"]) as run:
            nova_dns_ai._doh_cache.update(ts=12, value=True)
            self.assertTrue(nova_dns_ai.install_system_dns()["encrypted"])
            self.assertEqual(run.call_count, 2)
            script = run.call_args.args[0]
            self.assertIn("AllowFallbackToUdp=$false", script)
            self.assertIn("Windows не подтвердила обязательное шифрование", script)
            self.assertEqual(nova_dns_ai._doh_cache["ts"], 0)

    def test_timeout_rolls_back_static_and_dhcp_from_the_prewrite_snapshot(self):
        with mock.patch.object(nova_dns_ai, "is_windows_11", return_value=True), \
                mock.patch.object(nova_dns_ai, "_run_dns_setup", side_effect=[
                    self.snapshot(), subprocess.TimeoutExpired("powershell.exe", 45), ""]) as run:
            with self.assertRaisesRegex(RuntimeError, "прежние настройки восстановлены"):
                nova_dns_ai.install_system_dns()
            self.assertEqual(run.call_count, 3)
            rollback = run.call_args.args[0]
            self.assertIn("-ResetServerAddresses", rollback)
            self.assertIn("2606:4700:4700::1111", rollback)

    def test_rollback_failure_is_reported_alongside_apply_failure(self):
        with mock.patch.object(nova_dns_ai, "is_windows_11", return_value=True), \
                mock.patch.object(nova_dns_ai, "_run_dns_setup", side_effect=[
                    self.snapshot(), RuntimeError("apply failed"), RuntimeError("rollback failed")]):
            with self.assertRaisesRegex(RuntimeError, "apply failed.*rollback failed"):
                nova_dns_ai.install_system_dns()

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOVA = os.path.join(BASE, "nova.pyw")

# Отданы Unlocker (D8): у него живут правила AG_UNLOCKER_NRPT_V2 на те же имена,
# а два правила на один namespace дерутся.
UNLOCKER_OWNED = (
    "cloudcode-pa.googleapis.com",
    "daily-cloudcode-pa.googleapis.com",
    "generativelanguage.googleapis.com",
)


def _module_tree():
    return ast.parse(io.open(NOVA, encoding="utf-8").read(), filename=NOVA)


def _assignment(name, tree=None):
    tree = tree if tree is not None else _module_tree()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if any(getattr(target, "id", "") == name for target in node.targets):
            return node
    raise AssertionError(f"{name} не найдено в nova.pyw")


def _constant(name, tree=None):
    return ast.literal_eval(_assignment(name, tree).value)


def _domain_list(name):
    path = os.path.join(BASE, "list", name)
    domains = set()
    with io.open(path, encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip().lower()
            if line:
                domains.add(line)
    return domains


def _match_domain(domains, host):
    """Как matchDomain в сгенерированном PAC: имя и любой его родительский суффикс."""
    host = str(host or "").strip(".").lower()
    while host:
        if host in domains:
            return True
        if "." not in host:
            return False
        host = host.split(".", 1)[1]
    return False


class NrptNamespaceTests(unittest.TestCase):
    def setUp(self):
        tree = _module_tree()
        self.namespaces = list(_constant("NOVA_NRPT_NAMESPACES", tree))
        self.extra = list(_constant("NOVA_AI_KILLSWITCH_EXEMPT_EXTRA", tree))
        self.ai_unlock = {
            str(item).lstrip(".").strip().lower()
            for item in self.namespaces + self.extra
            if str(item).strip()
        }

    def test_no_duplicates(self):
        """Дубль namespace — это лишнее правило NRPT и лишний процесс на старте."""
        self.assertEqual(len(self.namespaces), len(set(self.namespaces)))

    def test_unlocker_names_are_not_taken_back(self):
        """D8: их держит вторая программа владельца, спор за namespace не нужен."""
        for host in UNLOCKER_OWNED:
            self.assertNotIn(host, self.namespaces)

    def test_youtube_is_only_the_accounts_host(self):
        """Новый список разблокирует accounts.youtube.com и ничего больше."""
        self.assertIn("accounts.youtube.com", self.namespaces)
        self.assertNotIn("youtube.com", self.namespaces)
        self.assertNotIn(".youtube.com", self.namespaces)

    def test_youtube_still_routes_through_warp(self):
        """Маршрут задаёт list/main.txt, и уход из NRPT его не касается."""
        self.assertIn("youtube.com", _domain_list("main.txt"))

    def test_ai_unlock_is_derived_not_hand_maintained(self):
        """I7 держит два числа; здесь пришпилено, как одно получается из другого."""
        self.assertEqual(len(self.namespaces), 32)
        self.assertEqual(len(self.ai_unlock), 33)

    def test_ai_unlock_direct_branch_over_a_warp_domain_is_a_conscious_list(self):
        """`matchDomain(ai_unlock, host) && matchDomain(eu, host)` отдаёт DIRECT.

        Пока Opera жива, ветки нет вовсе; когда она лежит, домен из этого
        пересечения идёт напрямую — в том числе мимо WARP, если он же покрыт
        list/main.txt. Для ИИ-сервисов это и задумано (WARP они блокируют сами),
        для домена, который в РФ без VPN не открывается, — это поломка.
        Поэтому список пересечения зафиксирован поимённо: новое имя обязано
        попасть сюда осознанно, а не проехать вместе с очередной правкой.

        `copilot.microsoft.com` — старая запись: `microsoft.com` лежит в
        list/main.txt, и уход в DIRECT здесь ровно то, ради чего заведён
        NOVA_AI_KILLSWITCH_EXEMPT_EXTRA. `gql.twitch.tv` приехал вместе с новым
        списком NRPT: при лежащей Opera Twitch API пойдёт напрямую, а не через
        WARP.
        """
        eu_domains = _domain_list("second.txt")
        ru_domains = _domain_list("main.txt")
        overlapping = sorted(
            host
            for host in self.ai_unlock
            if _match_domain(eu_domains, host) and _match_domain(ru_domains, host)
        )
        self.assertEqual(overlapping, ["copilot.microsoft.com", "gql.twitch.tv"])


class NrptCascadeTests(unittest.TestCase):
    def setUp(self):
        self.tree = _module_tree()
        self.cascade = list(_constant("NOVA_NRPT_NAMESERVER_CASCADE", self.tree))

    def test_cascade_order_is_the_one_the_owner_asked_for(self):
        providers = [str(provider) for provider, _addresses in self.cascade]
        self.assertEqual(providers, ["dns-ai.ru", "comss.one", "geohide.ru"])

    def test_every_provider_has_at_least_one_address(self):
        for provider, addresses in self.cascade:
            self.assertTrue(addresses, f"{provider} без адресов — молчаливая дыра в каскаде")

    def test_addresses_are_unique_across_the_cascade(self):
        """Повтор адреса — лишний таймаут на том же сервере, а не ещё одна попытка."""
        flat = [str(address).lower() for _provider, addresses in self.cascade for address in addresses]
        self.assertEqual(len(flat), len(set(flat)))

    def test_dns_ai_server_set_is_derived_from_the_cascade(self):
        """Проверка «системный DNS уже dns-ai» обязана смотреть на те же адреса.

        Вторая копия адресов рядом означала бы, что индикатор и правила могут
        разойтись после правки одного из списков.
        """
        node = _assignment("NOVA_DNS_AI_SERVERS", self.tree)
        source = ast.get_source_segment(io.open(NOVA, encoding="utf-8").read(), node)
        self.assertIn("NOVA_NRPT_NAMESERVER_CASCADE", source or "")

    def test_powershell_literal_is_built_from_the_cascade(self):
        """Та же причина: строка для @(...) собирается, а не пишется руками."""
        node = _assignment("NOVA_NRPT_NAMESERVERS", self.tree)
        source = ast.get_source_segment(io.open(NOVA, encoding="utf-8").read(), node)
        self.assertIn("_nrpt_nameservers_ps_literal()", source or "")


if __name__ == "__main__":
    unittest.main()
