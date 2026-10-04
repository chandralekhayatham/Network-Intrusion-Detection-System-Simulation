# Architecture
Synthetic Traffic -> Flow Collection -> Feature Extraction -> Signature Detection + Anomaly Detection + Optional ML -> Risk Engine -> Alert Engine -> SQLite -> SOC Dashboard -> Analyst Investigation.
All suspicious behavior is synthetic flow DATA; no packets are sent.
