#!/usr/bin/env python3
"""Derive a ProxMoxSDN expectations file from zones.yml + policies.yml (+ the documented
companion-band rules of vyos-commands.j2), independently of the rendered gateway configs.

usage: gen_expectations.py <repo_root> <out.yml>
"""
import hashlib, json, subprocess, sys
import yaml

repo, out = sys.argv[1], sys.argv[2]
V = f"{repo}/vyos/ansible/vars"
zones_doc = yaml.safe_load(open(f"{V}/zones.yml"))
pol_doc = yaml.safe_load(open(f"{V}/policies.yml"))
prod = yaml.safe_load(open(f"{V}/production.yml"))
features = prod.get("features", {})

zones = {z["name"]: z for z in zones_doc["zones"]}
tier = {n: z.get("trust_tier") for n, z in zones.items()}
by_tier = {}
for n, t in tier.items():
    by_tier.setdefault(t, []).append(n)

agroups = pol_doc.get("firewall_address_groups") or {}
ngroups = pol_doc.get("firewall_network_groups") or {}
universal_local = pol_doc.get("universal_to_local_rules") or []
universal_sec = pol_doc.get("universal_to_security_rules") or []


def rule_spec(r, frm, to):
    """policies.yml rule -> flow spec (lists of strings; None = any)."""
    s = {"policy_rule": r.get("number"), "action": r.get("action"), "description": r.get("description", "")[:120]}
    src = []
    if "source_address" in r:
        src.append(str(r["source_address"]))
    if "source_group" in r:
        src += [str(x) for x in agroups.get(r["source_group"], [])] or ["__EMPTY__"]
        s["source_group"] = r["source_group"]
    if "source_network_group" in r:
        src += [str(x) for x in ngroups.get(r["source_network_group"], [])] or ["__EMPTY__"]
        s["source_network_group"] = r["source_network_group"]
    dst = []
    if "destination_address" in r:
        dst.append(str(r["destination_address"]))
    if "destination_group" in r:
        dst += [str(x) for x in agroups.get(r["destination_group"], [])] or ["__EMPTY__"]
        s["destination_group"] = r["destination_group"]
    if "destination_network_group" in r:
        dst += [str(x) for x in ngroups.get(r["destination_network_group"], [])] or ["__EMPTY__"]
        s["destination_network_group"] = r["destination_network_group"]
    s["src"] = src or None
    s["dst"] = dst or None
    s["protocol"] = r.get("protocol")
    s["dst_ports"] = str(r["destination_port"]) if "destination_port" in r else None
    s["src_ports"] = str(r["source_port"]) if "source_port" in r else None
    s["state_only"] = bool(r.get("state"))
    return s


def expand_rules(p):
    rules = p.get("rules") or []
    if isinstance(rules, str):
        if "universal_to_local_rules" in rules:
            rules = universal_local
        elif "universal_to_security_rules" in rules:
            rules = universal_sec
        else:
            raise SystemExit(f"unexpected rules template {rules!r} in {p['from_zone']}->{p['to_zone']}")
    out = list(rules)  # universal_* lists apply only via the template string (renderer/adapters.py); never injected
    return sorted(out, key=lambda r: r.get("number", 0))


pairs = {}
for p in pol_doc["policies"]:
    key = f"{p['from_zone']}->{p['to_zone']}"
    pairs[key] = {
        "from": p["from_zone"], "to": p["to_zone"], "default_action": p.get("default_action", "drop"),
        "suppress_icmp_companion": bool(p.get("suppress_icmp_companion")),
        "suppress_tcp_companion": bool(p.get("suppress_tcp_companion")),
        "rules": [rule_spec(r, p["from_zone"], p["to_zone"]) for r in expand_rules(p)],
    }

# documented template behaviour (vyos-commands.j2, companion band #551 Phase D / #919 C4)
remove_ack = bool(features.get("remove_cross_node_ack_rules"))


def keep_ack_band(frm, to):
    return (not remove_ack) or frm in ("pkicore", "pkidmz") or to in ("pkicore", "pkidmz") or (frm == "backup" and to == "wan")


internal = [z for z in zones]
adv, crit, high = by_tier.get("ADVERSARIAL", []), by_tier.get("CRITICAL", []), by_tier.get("HIGH", [])
PUBLIC = ["0.0.0.0/0"]
NON_PUBLIC = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8",
              "169.254.0.0/16", "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4"]

assertions = []
assertions.append({"id": "T1-adversarial-to-critical-no-new-tcp-udp", "kind": "no-new-flows",
                   "from_zones": adv, "to_zones": crit, "protocols": ["tcp", "udp"], "flow_class": "new",
                   "why": "zones.yml: CRITICAL = strictest isolation; ADVERSARIAL = default-deny to all other zones"})
assertions.append({"id": "T2-no-ssh-into-critical", "kind": "no-new-flows",
                   "from_zones": [z for z in zones if z not in crit] + ["wan"], "to_zones": crit,
                   "protocols": ["tcp"], "dst_ports": "22", "flow_class": "new",
                   "why": "test_pki_zones_no_inbound_ssh; zones.yml CRITICAL tier"})
assertions.append({"id": "T3-no-internet-zones-internet-only-via-policy-pinholes", "kind": "allowed-subset-of-policy",
                   "from_zones": [z for z, d in zones.items() if d.get("internet_access") is False], "to_zones": ["wan"],
                   "flow_class": "new",
                   "why": "zones.yml internet_access: false. policies.yml nevertheless grants per-host internet pinholes "
                          "(e.g. backup->wan 100-106, knowledge->wan 100-101, agentedge->wan 100-101), so the checkable "
                          "invariant is: public destinations reachable only through those explicit policies.yml rules"})
for kind_id, frm_list, to_list, why in (
        ("S1", adv, [z for z in zones if z not in adv] + ["local"], "ADVERSARIAL egress must equal policies.yml pinholes"),
        ("S2", [z for z in zones if z not in crit] + ["wan"], crit, "every opening into CRITICAL must be a policies.yml rule"),
        ("S3", ["wan"], [z for z in zones] + ["local"], "internet ingress must equal policies.yml pinholes")):
    assertions.append({"id": f"{kind_id}-policy-subset", "kind": "allowed-subset-of-policy",
                       "from_zones": frm_list, "to_zones": to_list, "flow_class": "new",
                       "wan_sources": "public" if kind_id == "S3" else "any",
                       "why": why + " (allowed = policies.yml accept rules + universal rules + decided companions)"})
assertions.append({"id": "M1-policy-rules-honoured", "kind": "policy-rules-permitted", "flow_class": "new",
                   "why": "each stateless policies.yml accept rule must be fully permitted on every gateway hosting both zones"})
assertions.append({"id": "N1-nonsyn-tcp-only-where-documented", "kind": "nonsyn-tcp-scope", "flow_class": "invalid",
                   "remove_cross_node_ack_rules": remove_ack,
                   "why": "vyos-commands.j2 _keep_ack_band: rules 900/901 kept only on PKI pairs and backup->wan"})
assertions.append({"id": "D1-rule-902-icmp-into-critical", "kind": "decision", "decision": "rule_902_icmp_into_critical",
                   "from_zones": adv, "to_zones": crit, "protocols": ["icmp"], "flow_class": "new"})
assertions.append({"id": "D2-rule-902-icmp-internet-into-mgmt", "kind": "decision", "decision": "rule_902_icmp_from_internet",
                   "from_zones": ["wan"], "to_zones": ["mgmt"], "wan_sources": "public", "protocols": ["icmp"], "flow_class": "new"})

doc = {
    "version": 1,
    "generated_from": {
        "repo_commit": subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip(),
        "zones.yml_sha256": hashlib.sha256(open(f"{V}/zones.yml", "rb").read()).hexdigest(),
        "policies.yml_sha256": hashlib.sha256(open(f"{V}/policies.yml", "rb").read()).hexdigest(),
        "production.yml_sha256": hashlib.sha256(open(f"{V}/production.yml", "rb").read()).hexdigest(),
    },
    "tiers": tier,
    "zone_subnets": {n: z["subnet"] for n, z in zones.items()},
    "internet_access": {n: z.get("internet_access") for n, z in zones.items()},
    "decisions": {
        "rule_902_icmp_into_critical": {
            "question": "May new ICMP from ADVERSARIAL zones reach CRITICAL (PKI) hosts via companion rule 902?",
            "owner": "Jake", "status": "pending", "branches": ["allowed", "forbidden"]},
        "rule_902_icmp_from_internet": {
            "question": "May new ICMP from arbitrary internet sources reach mgmt hosts via wan-to-mgmt rule 902?",
            "owner": "Jake", "status": "pending", "branches": ["allowed", "forbidden"]},
    },
    "companions": {"icmp_902": "per-decision", "keep_ack_band": "features.remove_cross_node_ack_rules=%s" % remove_ack,
                   "universal_to_local_rules": len(universal_local), "universal_to_security_rules": len(universal_sec)},
    "pairs": pairs,
    "assertions": assertions,
}
yaml.safe_dump(doc, open(out, "w"), sort_keys=False, width=140)
print(out, "pairs", len(pairs), "assertions", len(assertions), "rules", sum(len(p["rules"]) for p in pairs.values()))
