from dataclasses import dataclass


def _normalize_country(value):
    country = str(value or "EU").strip().upper()
    return country if country in {"EU", "AM"} else "EU"


@dataclass(frozen=True)
class OperaFailoverDecision:
    country: str
    transport: str = "direct"
    full_proxy: str = ""
    reason: str = ""


class OperaFailoverController:
    """Pure state machine for Opera region/transport recovery."""

    def __init__(
        self,
        desired_country="EU",
        direct_failure_limit=3,
        warp_failure_limit=2,
        retry_base_sec=300.0,
        retry_max_sec=1800.0,
    ):
        self.direct_failure_limit = max(1, int(direct_failure_limit))
        self.warp_failure_limit = max(1, int(warp_failure_limit))
        self.retry_base_sec = max(30.0, float(retry_base_sec))
        self.retry_max_sec = max(self.retry_base_sec, float(retry_max_sec))
        self.desired_country = "EU"
        self.current_country = "EU"
        self.transport = "direct"
        self.full_proxy = ""
        self.direct_failures = 0
        self.warp_failures = 0
        self.retry_round = 0
        self.next_desired_retry_ts = 0.0
        self.set_desired_country(desired_country)

    def current_decision(self, reason=""):
        return OperaFailoverDecision(
            country=self.current_country,
            transport=self.transport,
            full_proxy=self.full_proxy if self.transport == "warp" else "",
            reason=str(reason or ""),
        )

    def set_desired_country(self, country):
        country = _normalize_country(country)
        self.desired_country = country
        self.current_country = country
        self.transport = "direct"
        self.full_proxy = ""
        self.direct_failures = 0
        self.warp_failures = 0
        self.retry_round = 0
        self.next_desired_retry_ts = 0.0
        return self.current_decision("desired-region")

    def record_success(self, now):
        if self.current_country == self.desired_country:
            self.direct_failures = 0
            self.warp_failures = 0
            self.retry_round = 0
            self.next_desired_retry_ts = 0.0
        elif not self.next_desired_retry_ts:
            self._schedule_desired_retry(now)

    def next_after_failure(self, now, warp_usable=False, warp_proxy=""):
        now = float(now)
        warp_proxy = str(warp_proxy or "").strip()

        if self.current_country != self.desired_country:
            if self.desired_retry_due(now):
                return self.begin_desired_retry()
            if not self.next_desired_retry_ts:
                self._schedule_desired_retry(now)
            return self.current_decision("alternate-retry")

        if self.transport == "warp":
            if not warp_usable or not warp_proxy:
                return self._switch_to_alternate(now, "desired-warp-unavailable")
            self.full_proxy = warp_proxy
            self.warp_failures += 1
            if self.warp_failures < self.warp_failure_limit:
                return self.current_decision("desired-warp-retry")
            return self._switch_to_alternate(now, "desired-warp-failed")

        self.direct_failures += 1
        if self.direct_failures < self.direct_failure_limit:
            return self.current_decision("desired-direct-retry")

        if self.desired_country == "EU" and warp_usable and warp_proxy:
            self.transport = "warp"
            self.full_proxy = warp_proxy
            self.warp_failures = 0
            return self.current_decision("desired-eu-over-warp")

        return self._switch_to_alternate(now, "desired-direct-failed")

    def desired_retry_due(self, now):
        return bool(
            self.current_country != self.desired_country
            and self.next_desired_retry_ts
            and float(now) >= self.next_desired_retry_ts
        )

    def begin_desired_retry(self):
        self.current_country = self.desired_country
        self.transport = "direct"
        self.full_proxy = ""
        self.direct_failures = 0
        self.warp_failures = 0
        self.next_desired_retry_ts = 0.0
        return self.current_decision("periodic-desired-retry")

    def runtime_label(self):
        region = "US" if self.current_country == "AM" else self.current_country
        return f"{region}/WARP" if self.transport == "warp" else region

    def _switch_to_alternate(self, now, reason):
        # Only EU has an explicit AM fallback. A user-selected US/AM region is
        # retried in place instead of silently changing to another region.
        if self.desired_country != "EU":
            self.direct_failures = 0
            self.warp_failures = 0
            return self.current_decision("desired-am-retry")

        self.current_country = "AM"
        self.transport = "direct"
        self.full_proxy = ""
        self.direct_failures = 0
        self.warp_failures = 0
        self._schedule_desired_retry(now)
        return self.current_decision(reason)

    def _schedule_desired_retry(self, now):
        delay = min(
            self.retry_max_sec,
            self.retry_base_sec * (2 ** min(self.retry_round, 6)),
        )
        self.retry_round += 1
        self.next_desired_retry_ts = float(now) + delay
        return delay


def build_full_dial_proxy_args(proxy):
    proxy = str(proxy or "").strip()
    return ["-proxy", proxy] if proxy else []
