#!/usr/bin/env python3
"""Regression tests for the as-validated Batfish translator (tools/batfish, #4909).

No Batfish service is needed: these pin what the translator emits and that its
compiled filters give the same verdict as the independent per-packet reference
evaluator (vyos_ref2) on a small fixture gateway.

  * Batfish workarounds, as emission contracts:
      - SYN-only TCP is `tcp-flags "(syn & !ack)"`, never `tcp-initial`
        (Batfish models tcp-initial as SYN regardless of ACK);
      - a NAT rule matches through one address-set reference per side, never
        repeated `match source-address` lines (Batfish keeps only the last);
      - a NAT `exclude` is `then source-nat off` ahead of later rules. Batfish
        models it as a matched no-op that ends source-NAT rule evaluation,
        which is exactly VyOS exclude semantics.
  * Differential: for every probe packet the first matching translated term
    agrees with vyos_ref2, and every packet the reference cannot decide falls
    inside an UNSUP region of its ingress interface (fail-closed, never a
    silent PASS).
"""
import ipaddress
import itertools
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import hset as H  # noqa: E402
from vyos2junos import Gateway, emit  # noqa: E402
from vyos_ref2 import Ref  # noqa: E402

FIXTURE = """
set system host-name 'vyos-gw-fix'
set interfaces ethernet eth0 address '10.9.0.2/24'
set interfaces ethernet eth1 address '10.9.1.1/24'
set interfaces ethernet eth2 address '10.9.2.1/24'
set interfaces ethernet eth3 address '10.9.3.1/24'
set protocols static route 0.0.0.0/0 next-hop '10.9.0.1'
set firewall group network-group PKI network '10.9.3.0/24'
set firewall group address-group SPOOFY address '10.9.1.77'
set firewall zone wan member interface 'eth0'
set firewall zone wan default-action drop
set firewall zone alpha member interface 'eth1'
set firewall zone alpha default-action drop
set firewall zone beta member interface 'eth2'
set firewall zone beta default-action drop
set firewall zone pki member interface 'eth3'
set firewall zone pki default-action drop
set firewall zone local local-zone
set firewall zone local default-action drop
set firewall zone beta from alpha firewall name 'alpha-to-beta'
set firewall zone pki from alpha firewall name 'alpha-to-pki'
set firewall zone wan from alpha firewall name 'alpha-to-wan'
set firewall zone local from alpha firewall name 'alpha-to-local'
set firewall zone alpha from wan firewall name 'wan-to-alpha'
set firewall ipv4 forward filter default-action 'accept'
set firewall ipv4 forward filter rule 6 action 'drop'
set firewall ipv4 forward filter rule 6 destination address '10.9.2.0/24'
set firewall ipv4 forward filter rule 6 protocol 'tcp'
set firewall ipv4 forward filter rule 6 destination port '3025'
set firewall ipv4 name alpha-to-beta default-action 'drop'
set firewall ipv4 name alpha-to-beta rule 1 action accept
set firewall ipv4 name alpha-to-beta rule 1 state established
set firewall ipv4 name alpha-to-beta rule 1 state related
set firewall ipv4 name alpha-to-beta rule 100 action accept
set firewall ipv4 name alpha-to-beta rule 100 protocol tcp
set firewall ipv4 name alpha-to-beta rule 100 destination port '443,3025'
set firewall ipv4 name alpha-to-beta rule 110 action drop
set firewall ipv4 name alpha-to-beta rule 110 source group address-group 'SPOOFY'
set firewall ipv4 name alpha-to-beta rule 120 action accept
set firewall ipv4 name alpha-to-beta rule 120 protocol udp
set firewall ipv4 name alpha-to-beta rule 120 destination port '53'
set firewall ipv4 name alpha-to-pki default-action 'drop'
set firewall ipv4 name alpha-to-pki rule 1 action accept
set firewall ipv4 name alpha-to-pki rule 1 state established
set firewall ipv4 name alpha-to-pki rule 1 state related
set firewall ipv4 name alpha-to-pki rule 900 action drop
set firewall ipv4 name alpha-to-pki rule 900 protocol tcp
set firewall ipv4 name alpha-to-pki rule 900 tcp flags syn
set firewall ipv4 name alpha-to-pki rule 900 tcp flags not ack
set firewall ipv4 name alpha-to-pki rule 901 action accept
set firewall ipv4 name alpha-to-pki rule 901 protocol tcp
set firewall ipv4 name alpha-to-pki rule 902 action accept
set firewall ipv4 name alpha-to-pki rule 902 protocol icmp
set firewall ipv4 name alpha-to-pki rule 998 action drop
set firewall ipv4 name alpha-to-pki rule 998 log
set firewall ipv4 name alpha-to-pki rule 998 limit rate '4/minute'
set firewall ipv4 name alpha-to-wan default-action 'drop'
set firewall ipv4 name alpha-to-wan rule 2 action jump
set firewall ipv4 name alpha-to-wan rule 2 jump-target 'alpha-to-pki'
set firewall ipv4 name alpha-to-wan rule 2 destination group network-group 'PKI'
set firewall ipv4 name alpha-to-wan rule 100 action accept
set firewall ipv4 name alpha-to-wan rule 100 protocol tcp
set firewall ipv4 name alpha-to-wan rule 100 destination port '443'
set firewall ipv4 name alpha-to-wan rule 200 action accept
set firewall ipv4 name alpha-to-wan rule 200 source address '10.9.1.50'
set firewall ipv4 name alpha-to-wan rule 200 source mac-address 'bc:24:11:00:00:01'
set firewall ipv4 name alpha-to-local default-action 'drop'
set firewall ipv4 name alpha-to-local rule 10 action accept
set firewall ipv4 name alpha-to-local rule 10 protocol udp
set firewall ipv4 name alpha-to-local rule 10 destination port '53'
set firewall ipv4 name wan-to-alpha default-action 'drop'
set firewall ipv4 name wan-to-alpha rule 1 action accept
set firewall ipv4 name wan-to-alpha rule 1 state established
set firewall ipv4 name wan-to-alpha rule 1 state related
set nat source rule 10 outbound-interface name 'eth0'
set nat source rule 10 destination address '10.0.0.0/8'
set nat source rule 10 exclude
set nat source rule 20 outbound-interface name 'eth0'
set nat source rule 20 source address '10.9.1.0/24'
set nat source rule 20 source group address-group 'SPOOFY'
set nat source rule 20 translation address 'masquerade'
set nat source rule 30 outbound-interface name 'eth0'
set nat source rule 30 source address '10.9.0.0/16'
set nat source rule 30 translation address '192.0.2.10'
"""

ADDRS = {
    "alpha": ["10.9.1.10", "10.9.1.50", "10.9.1.77"],
    "beta": ["10.9.2.20"],
    "pki": ["10.9.3.30"],
    "wan": ["8.8.8.8", "10.20.0.5"],
    "gw": ["10.9.1.1", "10.9.2.1", "10.9.0.2"],
}
IIF = {"eth0": "wan", "eth1": "alpha", "eth2": "beta", "eth3": "pki"}


def probes():
    srcs = {z: ADDRS[z] for z in ("alpha", "beta", "pki", "wan")}
    dsts = [a for z in ("alpha", "beta", "pki", "wan", "gw") for a in ADDRS[z]]
    shapes = [("tcp", 443, True, False), ("tcp", 3025, True, False), ("tcp", 22, True, False),
              ("tcp", 443, False, True), ("tcp", 22, False, True), ("udp", 53, False, False),
              ("udp", 123, False, False), ("icmp", 0, False, False)]
    for iif, zone in IIF.items():
        for src, dst, (proto, dport, syn, ack) in itertools.product(srcs[zone], dsts, shapes):
            if src == dst:
                continue
            ct = "new" if (proto != "tcp" or (syn and not ack)) else "invalid"
            yield {"iif": iif, "src": src, "dst": dst, "proto": proto, "sport": 40000 if proto != "icmp" else 0,
                   "dport": dport, "syn": syn, "ack": ack, "ct": ct}


def first_match(terms, pkt):
    for c, v, o in terms:
        if c.matches(pkt):
            return v, o
    raise AssertionError("no terminal term matched")


class EmissionContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cfg = {}
        for k in ("new", "est", "nat"):
            e, _, _ = emit(Gateway(FIXTURE, k), k)
            cls.cfg[k] = "\n".join(e.L)

    def test_syn_only_is_explicit_flags_never_tcp_initial(self):
        for k, text in self.cfg.items():
            self.assertNotIn("tcp-initial", text, k)
        self.assertIn('tcp-flags "(syn & !ack)"', self.cfg["new"])

    def test_nat_matches_one_address_set_per_side(self):
        nat = [ln for ln in self.cfg["nat"].splitlines() if "security nat source rule-set" in ln]
        self.assertFalse([ln for ln in nat if " match source-address " in ln or " match destination-address " in ln])
        per_rule = {}
        for ln in nat:
            if " match source-address-name " in ln:
                rule = ln.split(" match ")[0]
                per_rule[rule] = per_rule.get(rule, 0) + 1
        self.assertTrue(per_rule, "fixture NAT rules must exercise source matching")
        self.assertEqual(max(per_rule.values()), 1)

    def test_exclude_is_source_nat_off_ahead_of_later_rules(self):
        lines = [ln for ln in self.cfg["nat"].splitlines() if " then source-nat " in ln]
        thens = [ln.split(" then ")[1] for ln in lines]
        self.assertEqual(thens[0], "source-nat off", lines)
        self.assertEqual(len(thens), 3)


class TranslatorMatchesReference(unittest.TestCase):
    def test_new_class_verdicts_agree_and_undecidable_is_fenced(self):
        gw = Gateway(FIXTURE, "new")
        ref = Ref(FIXTURE, 0)
        terms = {i: gw.in_terms(i) for i in gw.enabled}
        checked = fenced = 0
        for p in probes():
            pkt = dict(p, src=int(ipaddress.ip_address(p["src"])), dst=int(ipaddress.ip_address(p["dst"])))
            rv, why, _ = ref.verdict(p)
            if rv == "unsupported":
                regions = [c for c, _, _ in gw.unsup_regions.get(p["iif"], [])]
                self.assertTrue(any(c.matches(pkt) for c in regions), f"not fenced: {p} ({why})")
                fenced += 1
                continue
            v, origin = first_match(terms[p["iif"]], pkt)
            got = "accept" if v == "accept" else "deny"
            want = "accept" if rv == "accept" else "deny"
            self.assertEqual(got, want, f"{p}: translator {origin} vs reference {why}")
            checked += 1
        self.assertGreater(checked, 300)
        self.assertGreater(fenced, 0, "the MAC-qualified rule must produce a fenced region")

    def test_unparsed_tcp_flags_fence_the_rule(self):
        text = FIXTURE + "\n".join([
            "set firewall ipv4 name alpha-to-beta rule 105 action accept",
            "set firewall ipv4 name alpha-to-beta rule 105 protocol tcp",
            "set firewall ipv4 name alpha-to-beta rule 105 tcp flags ack",
            "set firewall ipv4 name alpha-to-beta rule 105 tcp flags not syn",
        ])
        gw = Gateway(text, "new")
        gw.in_terms("eth1")
        why = [w for _, w, _ in gw.unsup_regions["eth1"]]
        self.assertTrue(any("alpha-to-beta:105" in w for w in why), why)


if __name__ == "__main__":
    unittest.main()
