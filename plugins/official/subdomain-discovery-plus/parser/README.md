# Parser

SentinelFlow v1alpha1 Manifests select trusted built-in parsers only. The
Manifest for this plugin uses `subdomain-discovery-plus-v1`, which is compiled
into the SentinelFlow runtime so plugin code is not loaded in-process.

`parser.py` mirrors that mapping for local plugin tests: runner findings become
informational `asset.subdomain` Finding drafts with structured Evidence data.
