import sys
import sqlite3
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from flask import Flask, jsonify, request, render_template
from ids.engine import rules, anomaly, risk, classification
from ids.correlation import correlate_alerts
from ids.incident import STATUS, incident_priority

app = Flask(__name__, template_folder='../frontend/templates')
ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / 'data' / 'ids.db'


def db():
    DB.parent.mkdir(exist_ok=True)
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init():
    c = db()
    c.executescript('''
    CREATE TABLE IF NOT EXISTS flows(
        flow_id TEXT PRIMARY KEY,timestamp TEXT,source_ip TEXT,destination_ip TEXT,
        source_port INT,destination_port INT,protocol TEXT,packet_count REAL,byte_count REAL,
        duration REAL,risk REAL,classification TEXT
    );
    CREATE TABLE IF NOT EXISTS alerts(
        alert_id TEXT PRIMARY KEY,flow_id TEXT,rule_id TEXT,alert_type TEXT,severity TEXT,
        description TEXT,risk REAL,status TEXT,created_at TEXT,source_ip TEXT
    );
    CREATE TABLE IF NOT EXISTS notes(
        id INTEGER PRIMARY KEY,alert_id TEXT,note TEXT,created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS incidents(
        incident_id TEXT PRIMARY KEY,title TEXT,source_ip TEXT,priority TEXT,status TEXT,
        alert_count INTEGER,risk REAL,created_at TEXT,updated_at TEXT,summary TEXT
    );
    ''')
    c.commit(); c.close()


def process(x):
    rs = rules(x)
    a = anomaly(x)
    r = risk(x)
    cl = classification(r)
    now = datetime.now().isoformat()
    c = db()
    c.execute('INSERT OR REPLACE INTO flows VALUES(?,?,?,?,?,?,?,?,?,?,?,?)', (
        x['flow_id'], x['timestamp'], x['source_ip'], x['destination_ip'],
        x['source_port'], x['destination_port'], x['protocol'], x['packet_count'],
        x['byte_count'], x['duration_seconds'], r, cl
    ))
    for i, z in enumerate(rs[:3]):
        aid = f"ALT-{datetime.now().strftime('%Y%m%d%H%M%S%f')}-{i}"
        sev = 'CRITICAL' if r > 80 else 'HIGH' if r > 60 else 'MEDIUM' if r > 40 else 'LOW'
        c.execute('INSERT INTO alerts VALUES(?,?,?,?,?,?,?,?,?,?)', (
            aid, x['flow_id'], z[0], z[1], sev, z[3], r, 'NEW', now, x['source_ip']
        ))
    c.commit(); c.close()
    return {'risk_score': r, 'classification': cl, 'anomaly_score': a, 'rules_triggered': [z[0] for z in rs]}


@app.route('/')
def home():
    return render_template('index.html')


@app.post('/api/flows')
def create():
    x = request.get_json(silent=True) or {}
    req = ['flow_id','timestamp','source_ip','destination_ip','source_port','destination_port','protocol','packet_count','byte_count','duration_seconds']
    miss = [k for k in req if k not in x]
    if miss:
        return jsonify(error='Missing fields', fields=miss), 400
    try:
        return jsonify(process(x)), 201
    except Exception as e:
        return jsonify(error=str(e)), 400


@app.get('/api/flows')
def flows():
    c = db(); r = c.execute('select * from flows order by timestamp desc limit 100').fetchall(); c.close()
    return jsonify([dict(x) for x in r])


@app.get('/api/alerts')
def alerts():
    c = db(); r = c.execute('select * from alerts order by created_at desc limit 100').fetchall(); c.close()
    return jsonify([dict(x) for x in r])


@app.put('/api/alerts/<aid>/status')
def status(aid):
    s = (request.get_json(silent=True) or {}).get('status')
    ok = {'NEW','INVESTIGATING','RESOLVED','FALSE_POSITIVE'}
    if s not in ok:
        return jsonify(error='Invalid status'), 400
    c = db(); n = c.execute('update alerts set status=? where alert_id=?', (s, aid)).rowcount
    c.commit(); c.close(); return jsonify(updated=bool(n))


@app.post('/api/alerts/<aid>/notes')
def note(aid):
    n = (request.get_json(silent=True) or {}).get('note', '').strip()
    if not n: return jsonify(error='Note required'), 400
    c = db(); c.execute('insert into notes(alert_id,note,created_at) values(?,?,datetime(\'now\'))', (aid, n)); c.commit(); c.close()
    return jsonify(saved=True), 201


@app.get('/api/dashboard/stats')
def stats():
    c = db(); q = lambda s: c.execute(s).fetchone()[0]
    out = {
        'total_flows': q('select count(*) from flows'),
        'normal_traffic': q("select count(*) from flows where classification='NORMAL'"),
        'suspicious_traffic': q("select count(*) from flows where classification!='NORMAL'"),
        'open_alerts': q("select count(*) from alerts where status in ('NEW','INVESTIGATING')"),
        'critical_alerts': q("select count(*) from alerts where severity='CRITICAL'"),
        'average_risk': round(c.execute('select coalesce(avg(risk),0) from flows').fetchone()[0], 2),
        'open_incidents': q("select count(*) from incidents where status!='CLOSED'")
    }
    c.close(); return jsonify(out)


@app.get('/api/dashboard/alerts')
def alertstats():
    c = db()
    out = {
        'severity': [dict(x) for x in c.execute('select severity,count(*) count from alerts group by severity')],
        'types': [dict(x) for x in c.execute('select alert_type,count(*) count from alerts group by alert_type order by count desc')],
        'protocols': [dict(x) for x in c.execute('select protocol,count(*) count from flows group by protocol')]
    }
    c.close(); return jsonify(out)


@app.get('/api/correlations')
def correlations():
    c = db(); rows = [dict(x) for x in c.execute('select * from alerts order by created_at').fetchall()]; c.close()
    return jsonify(correlate_alerts(rows))


@app.get('/api/incidents')
def incidents():
    c = db(); rows = [dict(x) for x in c.execute('select * from incidents order by created_at desc').fetchall()]; c.close()
    return jsonify(rows)


@app.post('/api/incidents')
def create_incident():
    data = request.get_json(silent=True) or {}
    source = data.get('source_ip', '').strip()
    if not source: return jsonify(error='source_ip is required'), 400
    c = db()
    rows = c.execute("select * from alerts where source_ip=? order by created_at desc limit 50", (source,)).fetchall()
    if not rows: c.close(); return jsonify(error='No alerts found for source_ip'), 404
    alerts_for_source = [dict(x) for x in rows]
    max_risk = max(float(x['risk']) for x in alerts_for_source)
    priority = incident_priority(max_risk, len(alerts_for_source))
    now = datetime.now().isoformat()
    incident_id = f"INC-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
    title = data.get('title') or f'Investigation for {source}'
    summary = data.get('summary') or f'{len(alerts_for_source)} correlated alert(s) from {source}.'
    c.execute('insert into incidents values(?,?,?,?,?,?,?,?,?,?)', (incident_id, title, source, priority, 'OPEN', len(alerts_for_source), max_risk, now, now, summary))
    c.commit(); c.close()
    return jsonify(incident_id=incident_id, priority=priority, status='OPEN'), 201


@app.put('/api/incidents/<iid>/status')
def incident_status(iid):
    status_value = (request.get_json(silent=True) or {}).get('status')
    if status_value not in STATUS: return jsonify(error='Invalid incident status'), 400
    c = db(); n = c.execute('update incidents set status=?,updated_at=? where incident_id=?', (status_value, datetime.now().isoformat(), iid)).rowcount
    c.commit(); c.close(); return jsonify(updated=bool(n))


@app.get('/api/ml/metrics')
def ml_metrics():
    path = ROOT / 'ml' / 'metrics.json'
    if not path.exists(): return jsonify(available=False, message='Run python ml/train_model.py first'), 404
    import json
    return jsonify(json.loads(path.read_text(encoding='utf-8')))


@app.post('/api/ml/evaluate')
def ml_evaluate():
    from ids.ml_detector import train_and_evaluate
    metrics = train_and_evaluate(str(ROOT / 'data' / 'network_traffic.csv'), str(ROOT / 'ml' / 'ids_model.joblib'), str(ROOT / 'ml' / 'metrics.json'))
    return jsonify(metrics)


if __name__ == '__main__':
    init(); app.run(debug=True, host='127.0.0.1', port=5000)

init()
