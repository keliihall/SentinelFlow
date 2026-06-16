# Parser Contract

The Manifest selects the trusted built-in parser `example-echo-v1`. The runtime
passes it a borrowed raw output reference plus task, run, step, tool, actor, and
correlation context. The parser emits a strict normalization envelope containing:

- normalized values
- one informational Finding
- structured synthetic-message Evidence
- standard errors, when applicable

The Normalizer validates the envelope and resulting `ToolOutput` before storage.
No parser code from this plugin directory is loaded in process.
