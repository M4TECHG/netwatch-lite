# Splunk integration

1. In Splunk: **Settings -> Data inputs -> HTTP Event Collector -> New Token** (sourcetype `netwatch:alert`, index e.g. `netwatch`).
2. Send alerts:

```bash
netwatch analyze capture.pcap auth.log \
  --splunk-url https://splunk.local:8088/services/collector/event \
  --splunk-token <HEC_TOKEN> --splunk-index netwatch
# lab with a self-signed certificate only: add --splunk-insecure
# preview the payload without sending:     add --splunk-dry-run
```

## Useful SPL

```spl
index=netwatch sourcetype="netwatch:alert" | stats count by event.severity, event.rule
index=netwatch sourcetype="netwatch:alert" event.severity IN (high, critical) | table _time event.id event.title event.src
index=netwatch sourcetype="netwatch:alert" | spath path=event.mitre{}.id output=technique | stats count by technique
```
