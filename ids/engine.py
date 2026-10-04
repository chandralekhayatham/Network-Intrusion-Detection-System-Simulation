def features(x):
    p=float(x.get("packet_count") or 0); b=float(x.get("byte_count") or 0); d=max(float(x.get("duration_seconds") or 0),0)
    c=float(x.get("connection_count") or 0); fail=float(x.get("failed_connection_count") or 0); syn=float(x.get("syn_count") or 0)
    return {"packets_per_second":p/d if d else 0,"bytes_per_second":b/d if d else 0,
            "failure_ratio":fail/c if c else 0,"syn_ratio":syn/p if p else 0,
            "connection_rate":c/d if d else c}
def rules(x):
    f=features(x); port=int(x.get("destination_port") or 0); r=[]
    if f["connection_rate"]>20:r.append(("IDS-001","High Connection Rate","HIGH","Excessive connection rate."))
    if f["failure_ratio"]>=.5 and f["connection_rate"]>=2:r.append(("IDS-002","Repeated Failed Connections","HIGH","Repeated failures require investigation."))
    if port>60000 or port in {4444,31337,9001}:r.append(("IDS-003","Unusual Destination Port","MEDIUM","Unusual destination port."))
    if f["syn_ratio"]>=.6 and int(x.get("syn_count") or 0)>=20:r.append(("IDS-004","SYN-Heavy Behavior","HIGH","SYN activity is unusually dominant."))
    if port in {4444,31337,9001,65000}:r.append(("IDS-005","Unusual Service-Port Activity","MEDIUM","Configured unusual service port."))
    if f["bytes_per_second"]>250000:r.append(("IDS-006","High Traffic Volume","HIGH","Byte rate exceeded threshold."))
    return r
def anomaly(x):
    f=features(x)
    zs=[abs((f["packets_per_second"]-5)/4),abs((f["bytes_per_second"]-15000)/12000),
        abs((f["connection_rate"]-2)/3),abs((f["failure_ratio"]-.05)/.12)]
    return round(min(100,sum(min(z,6) for z in zs)/len(zs)/4*100),2)
def risk(x,ml=None):
    rr=min(100,len(rules(x))*30+(20 if any(r[2]=="HIGH" for r in rules(x)) else 0))
    a=anomaly(x)
    return round(rr*.4+a*.3+ml*.3 if ml is not None else rr*.6+a*.4,2)
def classification(r):
    return "NORMAL" if r<=20 else ("SUSPICIOUS" if r<=60 else "POTENTIAL INTRUSION")
