"""My own tests: one per rule in the spec."""
import json
import subprocess
import sys

import pytest

from tmcheck.core import (Gap, Issue, ModelError, RankedThreat, applicable,
                          coverage_gaps, crossing_flows, load_model,
                          policy_findings, rank, validate)


def base():
    return {
        "zones": [{"id": "z_net", "trust": 0}, {"id": "z_core", "trust": 3}],
        "elements": [
            {"id": "ext", "kind": "external_entity", "zone": "z_net"},
            {"id": "proc", "kind": "process", "zone": "z_core"},
            {"id": "db", "kind": "data_store", "zone": "z_core"},
            {"id": "log", "kind": "data_store", "zone": "z_core", "is_log": True},
        ],
        "flows": [
            {"id": "f1", "source": "ext", "target": "proc", "protocol": "https",
             "authenticated": True},
            {"id": "f2", "source": "proc", "target": "db", "protocol": "tcp"},
        ],
        "threats": [],
    }


def codes(model):
    return {(i.ref, i.code) for i in validate(model)}


def threat(**kw):
    t = {"id": "T1", "target": "proc", "category": "S", "title": "x" * 20,
         "likelihood": 3, "impact": 3, "status": "open"}
    t.update(kw)
    return t


# ---- load
def write(tmp_path, text):
    p = tmp_path / "m.yaml"
    p.write_text(text, encoding="utf-8")
    return p


def test_load_unsafe_tag(tmp_path):
    p = write(tmp_path, "zones: !!python/object/apply:os.system ['echo pwned']\n")
    with pytest.raises(ModelError):
        load_model(p)


def test_load_bad_shapes(tmp_path):
    for text in ["- a\n- b\n", "zones: [\n", "zones: 5\n", "", "flows: {a: 1}\n"]:
        with pytest.raises(ModelError):
            load_model(write(tmp_path, text))
    with pytest.raises(ModelError):
        load_model(tmp_path / "missing.yaml")


def test_load_defaults(tmp_path):
    m = load_model(write(tmp_path, "zones:\n  - {id: a, trust: 1}\nflows:\n"))
    assert m["elements"] == [] and m["flows"] == [] and m["threats"] == []
    assert len(m["zones"]) == 1


# ---- applicable
def test_applicable():
    assert applicable("external_entity") == {"S", "R"}
    assert applicable("process") == set("STRIDE")
    assert applicable("data_store") == {"T", "I", "D"}
    assert applicable("data_store", is_log=True) == {"T", "I", "D", "R"}
    assert applicable("data_flow") == {"T", "I", "D"}
    with pytest.raises(ValueError):
        applicable("zone")


# ---- validate
def test_clean_model():
    assert validate(base()) == []


def test_duplicate_id_one_space():
    m = base()
    m["flows"][0]["id"] = "proc"
    m["threats"] = [threat(id="db", target="proc")]
    got = codes(m)
    assert ("proc", "DUPLICATE_ID") in got and ("db", "DUPLICATE_ID") in got
    assert len([i for i in validate(m) if i.ref == "proc" and i.code == "DUPLICATE_ID"]) == 1


def test_unknown_zone_and_refs():
    m = base()
    m["elements"][0]["zone"] = "nowhere"
    m["flows"].append({"id": "f9", "source": "proc", "target": "ghost", "protocol": "tls"})
    m["threats"] = [threat(target="ghost")]
    got = codes(m)
    assert ("ext", "UNKNOWN_ZONE") in got
    assert ("f9", "UNKNOWN_REF") in got
    assert ("T1", "UNKNOWN_REF") in got


def test_bad_kind():
    m = base()
    m["elements"][1]["kind"] = "thing"
    assert ("proc", "BAD_KIND") in codes(m)


@pytest.mark.parametrize("s,t", [("db", "log"), ("db", "db"), ("ext", "ext"),
                                 ("ext", "db"), ("db", "ext"), ("proc", "proc")])
def test_invalid_flow(s, t):
    m = base()
    m["elements"].append({"id": "ext2", "kind": "external_entity", "zone": "z_net"})
    if "ext" in (s, t) and s == t:
        pass
    m["flows"] = [{"id": "fx", "source": s, "target": t, "protocol": "tls"}]
    assert ("fx", "INVALID_FLOW") in codes(m)


def test_valid_flows_not_invalid():
    for s, t in [("ext", "proc"), ("proc", "ext"), ("proc", "db"), ("db", "proc")]:
        m = base()
        m["flows"] = [{"id": "fx", "source": s, "target": t, "protocol": "tls"}]
        assert validate(m) == []


@pytest.mark.parametrize("bad", [True, False, 4.0, "4", 0, 6, None, -1])
@pytest.mark.parametrize("field", ["likelihood", "impact"])
def test_bad_score(bad, field):
    m = base()
    m["threats"] = [threat(**{field: bad})]
    assert ("T1", "BAD_SCORE") in codes(m)


@pytest.mark.parametrize("good", [1, 5])
def test_good_score(good):
    m = base()
    m["threats"] = [threat(likelihood=good, impact=good)]
    assert validate(m) == []


def test_missing_score_key():
    m = base()
    t = threat()
    del t["impact"]
    m["threats"] = [t]
    assert ("T1", "BAD_SCORE") in codes(m)


@pytest.mark.parametrize("target,cat", [("db", "E"), ("db", "S"), ("db", "R"),
                                        ("ext", "T"), ("f1", "S"), ("f1", "R"), ("f1", "E")])
def test_inapplicable(target, cat):
    m = base()
    m["threats"] = [threat(target=target, category=cat)]
    assert ("T1", "INAPPLICABLE_CATEGORY") in codes(m)


def test_r_on_log_ok():
    m = base()
    m["threats"] = [threat(target="log", category="R")]
    assert validate(m) == []


@pytest.mark.parametrize("cat", ["s", "ST", "", None, "X", 5, ["S"]])
def test_bad_category(cat):
    m = base()
    m["threats"] = [threat(category=cat)]
    got = codes(m)
    assert ("T1", "BAD_CATEGORY") in got
    assert ("T1", "INAPPLICABLE_CATEGORY") not in got


def test_decisions():
    m = base()
    m["threats"] = [
        threat(id="A", status="mitigated", mitigation="   "),
        threat(id="B", status="mitigated"),
        threat(id="C", status="accepted"),
        threat(id="D", status="accepted", justification="\n"),
        threat(id="E", status="closed"),
        threat(id="F", status="mitigated", mitigation="mTLS at the gateway"),
        threat(id="G", status="accepted", justification="switch keeps signed log"),
        threat(id="H", status="open"),
    ]
    got = codes(m)
    assert {("A", "MISSING_MITIGATION"), ("B", "MISSING_MITIGATION"),
            ("C", "MISSING_JUSTIFICATION"), ("D", "MISSING_JUSTIFICATION"),
            ("E", "BAD_STATUS")} <= got
    assert not {r for r, _ in got} & {"F", "G", "H"}


def test_validate_sorted_no_dupes():
    m = base()
    m["threats"] = [threat(id="Z", likelihood=9), threat(id="A", impact=9)]
    out = validate(m)
    assert out == sorted(out, key=lambda i: (i.ref, i.code, i.message))
    assert len(out) == len(set(out))


# ---- crossing / coverage
def test_crossing_order_and_unknown():
    m = base()
    m["flows"] = [
        {"id": "z9", "source": "ext", "target": "proc", "protocol": "tls"},
        {"id": "f2", "source": "proc", "target": "db", "protocol": "tls"},
        {"id": "a1", "source": "proc", "target": "ext", "protocol": "tls"},
        {"id": "bad", "source": "proc", "target": "nope", "protocol": "tls"},
    ]
    assert crossing_flows(m) == ["z9", "a1"]


def test_gaps_scope_and_sorting():
    m = base()
    gaps = coverage_gaps(m)
    refs = {g.ref for g in gaps}
    assert refs == {"f1", "ext", "proc"}
    proc = [g.category for g in gaps if g.ref == "proc"]
    assert proc == ["S", "T", "R", "I", "D", "E"]
    assert [g.ref for g in gaps] == sorted(g.ref for g in gaps)
    assert Gap("f1", "T") in gaps and Gap("ext", "S") in gaps


@pytest.mark.parametrize("status,extra", [("open", {}), ("mitigated", {"mitigation": "x"}),
                                           ("accepted", {"justification": "y"})])
def test_any_status_covers(status, extra):
    m = base()
    m["threats"] = [threat(target="f1", category="T", status=status, **extra)]
    assert Gap("f1", "T") not in coverage_gaps(m)
    assert Gap("f1", "I") in coverage_gaps(m)


# ---- policy
def test_policy_encryption():
    m = base()
    m["flows"][0]["protocol"] = "HTTPS"
    assert policy_findings(m) == []
    m["flows"][0]["protocol"] = "http"
    assert policy_findings(m) == [Issue("f1", "UNENCRYPTED_CROSSING", "protocol 'http'")]


def test_policy_non_crossing_not_checked():
    m = base()  # f2 is plaintext but inside one zone
    assert [i.ref for i in policy_findings(m)] == []


def test_policy_unauthenticated_inbound():
    m = base()
    del m["flows"][0]["authenticated"]
    assert [(i.ref, i.code) for i in policy_findings(m)] == [("f1", "UNAUTHENTICATED_INBOUND")]
    m["flows"][0]["authenticated"] = False
    assert len(policy_findings(m)) == 1
    # outbound towards lower trust is not flagged
    m["flows"] = [{"id": "f3", "source": "proc", "target": "ext", "protocol": "tls"}]
    assert policy_findings(m) == []


def test_policy_equal_trust_not_flagged():
    m = base()
    m["zones"][0]["trust"] = 3
    del m["flows"][0]["authenticated"]
    assert policy_findings(m) == []


def test_policy_pii():
    m = base()
    m["elements"][2]["holds_pii"] = True
    assert [(i.ref, i.code) for i in policy_findings(m)] == [("db", "PII_STORE_WITHOUT_I_THREAT")]
    m["threats"] = [threat(target="db", category="T")]
    assert len(policy_findings(m)) == 1
    m["threats"] = [threat(target="db", category="I", status="accepted")]
    assert policy_findings(m) == []


# ---- rank
def test_rank():
    m = base()
    m["threats"] = [
        threat(id="T10", likelihood=3, impact=3),
        threat(id="T2", likelihood=3, impact=3),
        threat(id="T3", likelihood=5, impact=3),   # 15 high
        threat(id="T4", likelihood=2, impact=4),   # 8 medium
        threat(id="T5", likelihood=1, impact=7),   # invalid, skipped
        threat(id="T6", likelihood=True, impact=5),  # invalid, skipped
        threat(id="T7", likelihood=3, impact=2, status="mitigated", mitigation="m"),
        threat(id="T8", likelihood=1, impact=1),
        threat(id="T9", likelihood=4, impact=2),   # 8, impact 2 < T4's 4
    ]
    out = rank(m)
    assert [r.id for r in out] == ["T3", "T2", "T10", "T4", "T9", "T8"]
    assert out[0] == RankedThreat("T3", 15, "high")
    assert out[1].level == "medium" and out[-1].level == "low"
    assert [r.level for r in out if r.id in ("T4", "T9")] == ["medium", "medium"]
    assert RankedThreat("T10", 9, "medium") in out


# ---- CLI
def run(path):
    return subprocess.run([sys.executable, "-m", "tmcheck", str(path)],
                          capture_output=True, text=True)


def test_cli(tmp_path):
    r = run(tmp_path / "nope.yaml")
    assert r.returncode == 2
    p = write(tmp_path, "- not a mapping\n")
    assert run(p).returncode == 2
    import yaml
    p = tmp_path / "gaps.yaml"
    p.write_text(yaml.safe_dump(base()), encoding="utf-8")
    r = run(p)
    assert r.returncode == 1
    data = json.loads(r.stdout)
    assert set(data) == {"issues", "gaps", "policy", "ranked"}
    assert {"ref", "category"} <= set(data["gaps"][0])


def test_cli_clean(tmp_path):
    import yaml
    m = {"zones": [{"id": "z", "trust": 1}],
         "elements": [{"id": "p", "kind": "process", "zone": "z"}]}
    p = tmp_path / "ok.yaml"
    p.write_text(yaml.safe_dump(m), encoding="utf-8")
    r = run(p)
    assert r.returncode == 0, r.stdout + r.stderr
