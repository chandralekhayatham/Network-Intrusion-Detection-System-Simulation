import pytest
from ids.engine import features, rules, anomaly, risk, classification
from ids.correlation import correlate_alerts
from ids.incident import incident_priority


def base():
    return {"destination_port":443,"packet_count":10,"byte_count":3000,"duration_seconds":2,
            "connection_count":2,"failed_connection_count":0,"syn_count":1}


def rule_ids(x):
    return [r[0] for r in rules(x)]


def test_zero_duration(): assert features({**base(),"duration_seconds":0})["connection_rate"]==2

def test_normal(): assert rules(base())==[]

def test_connection(): assert "IDS-001" in rule_ids({**base(),"connection_count":80,"duration_seconds":1})

def test_failures(): assert "IDS-002" in rule_ids({**base(),"connection_count":20,"failed_connection_count":15,"destination_port":22})

def test_port(): assert "IDS-003" in rule_ids({**base(),"destination_port":65000})

def test_syn(): assert "IDS-004" in rule_ids({**base(),"packet_count":50,"syn_count":40})

def test_volume(): assert "IDS-006" in rule_ids({**base(),"byte_count":1000000,"duration_seconds":1})

def test_anomaly_range(): assert 0<=anomaly(base())<=100

def test_risk_range(): assert 0<=risk(base())<=100

def test_classification(): assert classification(10)=="NORMAL" and classification(90)=="POTENTIAL INTRUSION"

def test_feature_packets_per_second(): assert features({**base(),"packet_count":20,"duration_seconds":2})["packets_per_second"]==10

def test_feature_bytes_per_second(): assert features({**base(),"byte_count":8000,"duration_seconds":2})["bytes_per_second"]==4000

def test_feature_failure_ratio(): assert features({**base(),"connection_count":10,"failed_connection_count":4})["failure_ratio"]==0.4

def test_feature_syn_ratio(): assert features({**base(),"packet_count":20,"syn_count":10})["syn_ratio"]==0.5

def test_feature_connection_rate(): assert features({**base(),"connection_count":10,"duration_seconds":2})["connection_rate"]==5

def test_unusual_service_port_rule(): assert "IDS-005" in rule_ids({**base(),"destination_port":4444})

def test_rule_count_increases_with_multiple_signals():
    assert len(rules({**base(),"connection_count":80,"duration_seconds":1,"byte_count":1000000,"destination_port":65000})) >= 3

def test_anomaly_is_float(): assert isinstance(anomaly(base()), float)

def test_risk_normal_is_low(): assert risk(base()) < 41

def test_risk_suspicious_is_higher(): assert risk({**base(),"connection_count":80,"duration_seconds":1}) > risk(base())

def test_classification_boundary_normal(): assert classification(20)=="NORMAL"

def test_classification_boundary_suspicious(): assert classification(21)=="SUSPICIOUS"

def test_classification_boundary_potential(): assert classification(61)=="POTENTIAL INTRUSION"

def test_classification_zero(): assert classification(0)=="NORMAL"

def test_classification_hundred(): assert classification(100)=="POTENTIAL INTRUSION"

def test_risk_never_exceeds_100(): assert risk({**base(),"connection_count":1000,"duration_seconds":0.01,"byte_count":99999999,"destination_port":65000})<=100

def test_negative_duration_safe(): assert features({**base(),"duration_seconds":-5})["connection_rate"]==2

def test_zero_packets_safe(): assert features({**base(),"packet_count":0,"syn_count":0})["syn_ratio"]==0

def test_zero_connections_safe(): assert features({**base(),"connection_count":0,"failed_connection_count":0})["failure_ratio"]==0

def test_correlation_single_alert():
    a=[{"alert_id":"A1","source_ip":"192.0.2.10","rule_id":"IDS-001","severity":"HIGH","created_at":"2026-01-01T10:00:00"}]
    result=correlate_alerts(a)
    assert len(result)==1 and result[0]["alert_count"]==1

def test_correlation_same_source():
    a=[
      {"alert_id":"A1","source_ip":"192.0.2.10","rule_id":"IDS-001","severity":"HIGH","created_at":"2026-01-01T10:00:00"},
      {"alert_id":"A2","source_ip":"192.0.2.10","rule_id":"IDS-002","severity":"HIGH","created_at":"2026-01-01T10:02:00"},
    ]
    result=correlate_alerts(a)
    assert result[0]["alert_count"]==2 and result[0]["correlation_level"]=="HIGH"

def test_correlation_different_sources():
    a=[
      {"alert_id":"A1","source_ip":"192.0.2.10","rule_id":"IDS-001","severity":"HIGH","created_at":"2026-01-01T10:00:00"},
      {"alert_id":"A2","source_ip":"192.0.2.11","rule_id":"IDS-002","severity":"HIGH","created_at":"2026-01-01T10:01:00"},
    ]
    assert len(correlate_alerts(a))==2

def test_correlation_critical_level():
    a=[{"alert_id":str(i),"source_ip":"192.0.2.10","rule_id":f"IDS-00{i}","severity":"HIGH","created_at":f"2026-01-01T10:0{i}:00"} for i in range(1,5)]
    assert correlate_alerts(a)[0]["correlation_level"]=="CRITICAL"

def test_incident_priority_low(): assert incident_priority(10,1)=="LOW"

def test_incident_priority_medium(): assert incident_priority(40,1)=="MEDIUM"

def test_incident_priority_high(): assert incident_priority(70,1)=="HIGH"

def test_incident_priority_critical(): assert incident_priority(90,1)=="CRITICAL"
