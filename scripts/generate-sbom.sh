#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ! -f "$1" ]]; then
  echo "usage: $0 /path/to/rbvm-csv-platform-VERSION.jar" >&2
  exit 64
fi

jar_path="$1"
filename="$(basename "$jar_path")"
version="${filename#rbvm-csv-platform-}"
version="${version%.jar}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "JAR filename does not contain a semantic version" >&2
  exit 65
}
sha256="$(sha256sum "$jar_path" | cut -d' ' -f1)"
output="$(dirname "$jar_path")/rbvm-csv-platform-$version.spdx.json"

printf '%s\n' \
  '{' \
  '  "spdxVersion": "SPDX-2.3",' \
  '  "dataLicense": "CC0-1.0",' \
  '  "SPDXID": "SPDXRef-DOCUMENT",' \
  '  "name": "rbvm-csv-platform-'"$version"'",' \
  '  "documentNamespace": "https://github.com/tarrabmu-commits/rbvm-csv-platform/spdx/'"$version"'",' \
  '  "creationInfo": {' \
  '    "created": "2020-01-01T00:00:00Z",' \
  '    "creators": ["Tool: rbvm-generate-sbom"]' \
  '  },' \
  '  "packages": [{' \
  '    "name": "rbvm-csv-platform",' \
  '    "SPDXID": "SPDXRef-Package-rbvm-csv-platform",' \
  '    "versionInfo": "'"$version"'",' \
  '    "downloadLocation": "NOASSERTION",' \
  '    "filesAnalyzed": false,' \
  '    "licenseConcluded": "NOASSERTION",' \
  '    "licenseDeclared": "NOASSERTION",' \
  '    "copyrightText": "NOASSERTION",' \
  '    "checksums": [{' \
  '      "algorithm": "SHA256",' \
  '      "checksumValue": "'"$sha256"'"' \
  '    }]' \
  '  }],' \
  '  "relationships": [{' \
  '    "spdxElementId": "SPDXRef-DOCUMENT",' \
  '    "relationshipType": "DESCRIBES",' \
  '    "relatedSpdxElement": "SPDXRef-Package-rbvm-csv-platform"' \
  '  }]' \
  '}' > "$output"

printf '%s\n' "$output"
