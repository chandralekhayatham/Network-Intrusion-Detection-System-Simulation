import csv,random
from pathlib import Path
random.seed(42)
SC=["NORMAL_WEB","NORMAL_DNS","NORMAL_SSH","NORMAL_EMAIL","NORMAL_DATABASE",
"HIGH_CONNECTION_RATE","REPEATED_FAILED_CONNECTIONS","MULTI_PORT_PROBING_PATTERN",
"SYN_HEAVY_PATTERN","UNUSUAL_PORT_ACTIVITY","HIGH_TRAFFIC_VOLUME"]
IPS=["192.0.2.","198.51.100.","203.0.113."]
def make(i):
    bad=random.random()<.30
    s=random.choice(SC[5:] if bad else SC[:5])
    normal={"NORMAL_WEB":(443,"TCP"),"NORMAL_DNS":(53,"UDP"),"NORMAL_SSH":(22,"TCP"),
            "NORMAL_EMAIL":(587,"TCP"),"NORMAL_DATABASE":(5432,"TCP")}
    if not bad:
        port,proto=normal[s]; packets=random.randint(3,35); con=random.randint(1,4)
        failed=0; syn=random.randint(0,2); rst=0; duration=random.uniform(.5,15); bytes_=random.randint(500,10000)
    elif s=="HIGH_CONNECTION_RATE":
        port,proto=443,"TCP"; packets=random.randint(20,100); con=random.randint(30,100); failed=random.randint(0,12); syn=random.randint(20,80); rst=random.randint(0,8); duration=random.uniform(.05,1.2); bytes_=random.randint(2000,30000)
    elif s=="REPEATED_FAILED_CONNECTIONS":
        port,proto=22,"TCP"; packets=random.randint(5,30); con=random.randint(12,40); failed=random.randint(8,35); syn=random.randint(5,25); rst=random.randint(3,20); duration=random.uniform(.1,4); bytes_=random.randint(300,5000)
    elif s=="MULTI_PORT_PROBING_PATTERN":
        port,proto=random.randint(1,65000),"TCP"; packets=random.randint(1,12); con=random.randint(15,60); failed=random.randint(8,35); syn=random.randint(10,50); rst=random.randint(3,20); duration=random.uniform(.02,2); bytes_=random.randint(100,3000)
    elif s=="SYN_HEAVY_PATTERN":
        port,proto=random.choice([80,443,8080]),"TCP"; packets=random.randint(45,140); con=random.randint(20,90); failed=random.randint(5,30); syn=random.randint(40,120); rst=random.randint(5,40); duration=random.uniform(.1,2); bytes_=random.randint(1000,10000)
    elif s=="UNUSUAL_PORT_ACTIVITY":
        port,proto=random.choice([4444,31337,9001,65000]),"TCP"; packets=random.randint(10,60); con=random.randint(5,30); failed=random.randint(0,12); syn=random.randint(2,25); rst=random.randint(0,12); duration=random.uniform(.2,5); bytes_=random.randint(1000,15000)
    else:
        port,proto=random.choice([80,443]),"TCP"; packets=random.randint(500,2000); con=random.randint(10,50); failed=random.randint(0,8); syn=random.randint(5,40); rst=random.randint(0,10); duration=random.uniform(.5,4); bytes_=random.randint(500000,5000000)
    src=IPS[i%3]+str(random.randint(10,240)); dst=IPS[(i+1)%3]+str(random.randint(10,240))
    return [f"FLOW-{i+1:06d}",f"2026-01-01T{(i//3600)%24:02d}:{(i//60)%60:02d}:{i%60:02d}",src,dst,random.randint(1024,65535),port,proto,packets,bytes_,round(duration,3),con,failed,syn,rst,round(bytes_/max(packets,1),2),"SUSPICIOUS" if bad else "NORMAL",s]
def generate(n=5000,out="data/network_traffic.csv"):
    Path(out).parent.mkdir(exist_ok=True)
    head=["flow_id","timestamp","source_ip","destination_ip","source_port","destination_port","protocol","packet_count","byte_count","duration_seconds","connection_count","failed_connection_count","syn_count","rst_count","average_packet_size","label","scenario_type"]
    with open(out,"w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(head); w.writerows(make(i) for i in range(n))
    print(f"Generated {n} synthetic flow records -> {out}")
if __name__=="__main__": generate()
