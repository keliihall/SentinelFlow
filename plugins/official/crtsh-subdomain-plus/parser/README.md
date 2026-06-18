# Parser

The manifest selects trusted built-in parser `crtsh-subdomain-plus-v1`.

The parser maps runner `subdomain_finding` records to `asset.subdomain`
Findings and `certificate_asset` records to `asset.tls_certificate` Findings.
It preserves SAN names, issuer, serial number, certificate transparency entry
IDs, first/last seen timestamps, wildcard-cleaning markers, and source details
as structured Evidence data.
