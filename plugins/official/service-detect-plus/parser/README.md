# service-detect-plus Parser

The manifest selects trusted built-in parser `service-detect-plus-v1`.

`parser.py` mirrors the built-in parser for plugin-local tests and documentation.
Normal SentinelFlow execution validates runner output, converts service results
to Finding/Evidence through the trusted runtime parser, and then persists only
normalized protocol resources.
