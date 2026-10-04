STATUS = {'OPEN', 'INVESTIGATING', 'CONTAINED', 'CLOSED'}

def incident_priority(risk_score, alert_count=1):
    score = float(risk_score) + min(int(alert_count), 5) * 5
    if score >= 90: return 'CRITICAL'
    if score >= 70: return 'HIGH'
    if score >= 40: return 'MEDIUM'
    return 'LOW'
