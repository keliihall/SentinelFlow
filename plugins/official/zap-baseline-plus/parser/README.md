# Built-in parser

The manifest selects `zap-baseline-plus-v1`, a trusted parser compiled into
`sentinelflow-runtime`. It accepts only schema-validated `zap_alert_result`
records and emits `risk.web_scan` findings with `zap-baseline-alert` evidence.
