from datetime import datetime


def correlate_alerts(alerts, window_minutes=5):
    """Group alerts from the same source IP within a time window."""
    groups = []
    for alert in sorted(alerts, key=lambda x: x.get('created_at', '')):
        source = alert.get('source_ip')
        try:
            current = datetime.fromisoformat(str(alert.get('created_at', '')).replace('Z', '+00:00'))
        except ValueError:
            current = None
        target = None
        for group in reversed(groups):
            if group['source_ip'] != source:
                continue
            if current is None or group['last_time'] is None or abs((current - group['last_time']).total_seconds()) <= window_minutes * 60:
                target = group
                break
        if target is None:
            target = {'source_ip': source, 'alert_count': 0, 'rule_ids': [], 'severities': [], 'alert_ids': [], 'last_time': current}
            groups.append(target)
        target['alert_count'] += 1
        target['alert_ids'].append(alert.get('alert_id'))
        if alert.get('rule_id') not in target['rule_ids']:
            target['rule_ids'].append(alert.get('rule_id'))
        if alert.get('severity') not in target['severities']:
            target['severities'].append(alert.get('severity'))
        if current and (target['last_time'] is None or current > target['last_time']):
            target['last_time'] = current
    for group in groups:
        group['correlation_level'] = 'CRITICAL' if group['alert_count'] >= 4 else 'HIGH' if group['alert_count'] >= 2 else 'LOW'
        group.pop('last_time', None)
    return groups
