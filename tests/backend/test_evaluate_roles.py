"""
Role evaluation against Kubernetes ground truth (server/evaluate_roles.py).
"""
import pytest

import evaluate_roles
from models import PodIpSighting, RoleSnapshot, db, utc_from_timestamp

AMF = ("AMF", frozenset({"AMF"}))
GNB = ("gNB", frozenset({"gNB", "E2_NODE"}))
TRUTH = {"10.0.0.1": AMF, "10.0.0.2": GNB}


def truth(ip, ts):
    return TRUTH.get(ip)


class TestScores:
    def test_precision_recall_and_accuracy(self):
        rows = [
            ("dpi", 60.0, "10.0.0.1", "AMF"),
            ("dpi", 60.0, "10.0.0.2", "E2_NODE"),     # also right for a gNB
            ("dpi", 120.0, "10.0.0.1", "SMF"),        # wrong
            ("dpi", 120.0, "10.0.0.2", "Unidentified"),
            ("dpi", 120.0, "10.16.0.9", "External/DN"),  # no pod: not labelled
        ]
        r = evaluate_roles.evaluate(rows, truth)["dpi"]
        assert (r["snapshots"], r["rows"], r["labelled_rows"]) == (2, 5, 4)
        assert r["accuracy"] == 0.5
        assert r["unidentified_rate"] == 0.25
        assert r["recall"] == {"AMF": 0.5, "gNB": 0.5}
        assert r["precision"] == {"AMF": 1.0, "E2_NODE": 1.0, "SMF": 0.0, "Unidentified": 0.0}
        assert r["confusion"]["AMF"] == {"AMF": 1, "SMF": 1}

    def test_sources_are_scored_separately(self):
        rows = [("dpi", 60.0, "10.0.0.1", "AMF"), ("pcap", 300.0, "10.0.0.1", "Unidentified")]
        results = evaluate_roles.evaluate(rows, truth)
        assert results["dpi"]["accuracy"] == 1.0
        assert results["pcap"]["accuracy"] == 0.0

    def test_no_labelled_rows(self):
        r = evaluate_roles.evaluate([("dpi", 1.0, "9.9.9.9", "AMF")], truth)["dpi"]
        assert r["accuracy"] is None and r["recall"] == {}


class TestReidentification:
    def test_delay_until_the_first_right_snapshot(self):
        rows = [
            ("dpi", 1000.0, "10.0.0.1", "AMF"),          # before the restart: ignored
            ("dpi", 1060.0, "10.0.0.1", "Unidentified"),
            ("dpi", 1120.0, "10.0.0.1", "AMF"),
            ("dpi", 1180.0, "10.0.0.1", "AMF"),
        ]
        starts = [("10.0.0.1", 1050.0, "AMF", frozenset({"AMF"}))]
        re_id = evaluate_roles.evaluate(rows, truth, starts)["dpi"]["reidentification"]
        assert re_id == {"pod_starts": 1, "identified": 1, "median_seconds": 70.0,
                         "max_seconds": 70.0, "not_identified": []}

    def test_pods_never_identified_are_listed(self):
        starts = [("10.0.0.2", 0.0, "gNB", frozenset({"gNB"}))]
        re_id = evaluate_roles.evaluate([("pcap", 300.0, "10.0.0.2", "UE")], truth, starts)[
            "pcap"]["reidentification"]
        assert re_id["identified"] == 0
        assert re_id["not_identified"] == [{"ip": "10.0.0.2", "role": "gNB", "started": 0.0}]


def test_database_evaluation(app, fresh_db):
    """Ground truth from stored pod sightings and the hint table."""
    t = 1_789_000_000.0
    with app.app_context():
        db.session.add_all([
            PodIpSighting(ip="10.244.0.31", namespace="team-5g", pod="open5gs-amf-abc",
                          labels={"app": "open5gs-amf"}, first_seen=utc_from_timestamp(t),
                          last_seen=utc_from_timestamp(t + 600)),
            RoleSnapshot(ts=t + 60, ip_address="10.244.0.31", role="Unidentified",
                         confidence=0, reasoning="", source="dpi"),
            RoleSnapshot(ts=t + 120, ip_address="10.244.0.31", role="AMF",
                         confidence=0.95, reasoning="", source="dpi"),
            RoleSnapshot(ts=t + 300, ip_address="10.244.0.31", role="AMF",
                         confidence=0.95, reasoning="", source="pcap"),
        ])
        db.session.commit()
        results = evaluate_roles.evaluate_database(t - 10, t + 700)
    assert results["dpi"]["accuracy"] == 0.5
    assert results["dpi"]["reidentification"]["median_seconds"] == 120.0
    assert results["pcap"]["reidentification"]["median_seconds"] == 300.0
    text = evaluate_roles.markdown(results, t - 10, t + 700)
    assert "## Source: dpi" in text and "| AMF | 2 | 50.0% |" in text
