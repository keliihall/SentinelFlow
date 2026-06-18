# dns-resolve-plus Parser

The manifest selects trusted built-in parser `dns-resolve-plus-v1`.

`parser.py` mirrors that parser for plugin-local tests and documentation. During
normal SentinelFlow execution the runner output is validated by
`schemas/output.schema.json`, converted to normalized Finding/Evidence by the
trusted runtime parser, and then handled by the Normalizer and Store.
