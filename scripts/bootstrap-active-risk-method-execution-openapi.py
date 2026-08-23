#!/usr/bin/env python3
from pathlib import Path

path = Path('api/openapi.yaml')
text = path.read_text(encoding='utf-8')
execute = "  /active-risk-method-executions/{activationRevision}/{activationEventSha256}/{inputSnapshotSha256}: {$ref: './active-risk-method-execution-v1.openapi.yaml#/paths/~1api~1v1~1active-risk-method-executions~1{activationRevision}~1{activationEventSha256}~1{inputSnapshotSha256}'}\n"
binding = "  /active-risk-method-execution-bindings/{bindingSha256}: {$ref: './active-risk-method-execution-v1.openapi.yaml#/paths/~1api~1v1~1active-risk-method-execution-bindings~1{bindingSha256}'}\n"

if execute in text and binding in text:
    print('Combined OpenAPI already contains active execution paths')
    raise SystemExit(0)
if execute in text or binding in text:
    raise SystemExit('combined OpenAPI contains only one active execution path')
marker = '\ncomponents:\n'
if text.count(marker) != 1:
    raise SystemExit(f'expected one root components marker, found {text.count(marker)}')
text = text.replace(marker, '\n' + execute + binding + 'components:\n', 1)
path.write_text(text, encoding='utf-8')
print('Combined OpenAPI active execution paths: PATCHED')
