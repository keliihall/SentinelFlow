# Parser Contract

The trusted built-in parser `nuclei-adapter-plus-v1` converts runner output
items with `type=nuclei_result` into SentinelFlow Findings:

- `findingType`: `risk.web_scan`
- `evidenceType`: `nuclei-template-result`
- target: matched URL or host
- preserved metadata: template id/path/name/severity/tags, matcher, extractor,
  CVE/CWE/CVSS, references, extracted results, request metadata, and source
  details

The runner must validate and normalize the Nuclei JSONL payload before the
parser receives it.
