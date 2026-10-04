import argparse,random,time,requests,datetime
IPS=["192.0.2.10","198.51.100.20","203.0.113.30"]
def flow(mode):
    bad=mode=="mixed" and random.random()<.45
    if bad:
        typ=random.choice(["high","fail","syn","port","volume"])
        if typ=="high": p,con,fail,syn,b,d=443,70,4,55,10000,.4
        elif typ=="fail": p,con,fail,syn,b,d=22,25,20,15,1500,1
        elif typ=="syn": p,con,fail,syn,b,d=80,50,15,85,5000,.5
        elif typ=="port": p,con,fail,syn,b,d=65000,40,25,30,500,.2
        else:p,con,fail,syn,b,d=443,30,2,10,3000000,2
    else:
        p=random.choice([443,53,22,587,5432]);con=2;fail=0;syn=1;b=3500;d=3
    return {"flow_id":"SIM-"+datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"),"timestamp":datetime.datetime.now().isoformat(),
    "source_ip":random.choice(IPS),"destination_ip":random.choice(IPS),"source_port":random.randint(1024,65535),
    "destination_port":p,"protocol":"UDP" if p==53 else "TCP","packet_count":15 if not bad else (1500 if b>100000 else 80),
    "byte_count":b,"duration_seconds":d,"connection_count":con,"failed_connection_count":fail,"syn_count":syn,"rst_count":0}
p=argparse.ArgumentParser();p.add_argument("--mode",choices=["normal","mixed"],default="mixed");p.add_argument("--speed",choices=["slow","fast"],default="slow");a=p.parse_args()
while True:
    try: print(requests.post("http://127.0.0.1:5000/api/flows",json=flow(a.mode),timeout=3).json())
    except Exception as e: print(e)
    time.sleep(1 if a.speed=="fast" else 4)
