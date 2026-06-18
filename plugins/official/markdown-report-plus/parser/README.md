# Parser

The manifest selects trusted built-in parser `markdown-report-plus-v1`.

The parser accepts runner output with `source=markdown-report-plus`, validates
`report.type=markdown_report`, and emits one standard Finding containing report
generation evidence. The Markdown body remains in normalized values and is also
referenced in evidence metadata so downstream report/store layers can persist or
export it without trusting raw adapter output.
