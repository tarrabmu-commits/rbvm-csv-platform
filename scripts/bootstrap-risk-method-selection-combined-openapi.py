#!/usr/bin/env python3
from pathlib import Path

path = Path('api/openapi.yaml')
text = path.read_text()
if '/risk-method-selection-policies/{revision}/{policySha256}:' in text:
    raise SystemExit('combined OpenAPI already contains risk-method policy routes')
marker = '\ncomponents:\n'
if text.count(marker) != 1:
    raise SystemExit(f'expected one components marker, found {text.count(marker)}')
block = r'''
  /risk-method-selection-policies/{revision}/{policySha256}:
    get:
      operationId: getRiskMethodSelectionPolicy
      summary: Read one exact immutable primary risk-method selection policy
      parameters:
        - name: revision
          in: path
          required: true
          schema: { type: integer, minimum: 1 }
        - name: policySha256
          in: path
          required: true
          schema: { type: string, pattern: '^[a-f0-9]{64}$' }
      responses:
        '200':
          description: Exact policy revision and canonical SHA identity
          headers:
            ETag: { schema: { type: string } }
            Location: { schema: { type: string } }
          content:
            application/json:
              schema: { type: object }
        '400': { $ref: '#/components/responses/Problem' }
        '401': { $ref: '#/components/responses/AuthenticationRequired' }
        '403': { $ref: '#/components/responses/InsufficientRole' }
        '404': { $ref: '#/components/responses/Problem' }
        '429': { $ref: '#/components/responses/RateLimited' }
        '503': { $ref: '#/components/responses/Problem' }
  /risk-method-selection-policy-installations/{revision}/{methodFamily}/{methodId}/{methodVersion}/{methodSha256}:
    post:
      operationId: installRiskMethodSelectionPolicy
      summary: Install or replay one explicit immutable primary risk-method policy revision
      description: >-
        Requires OPERATOR. Every selected method identity is explicit; the route has no
        current, latest, default, fallback, catalog-order, or score-averaging semantic.
      parameters:
        - name: revision
          in: path
          required: true
          schema: { type: integer, minimum: 1 }
        - name: methodFamily
          in: path
          required: true
          schema: { type: string, enum: [RBVM_FORMULA, STANDARD_DERIVED] }
        - name: methodId
          in: path
          required: true
          schema: { type: string, minLength: 1 }
        - name: methodVersion
          in: path
          required: true
          schema: { type: integer, minimum: 1 }
        - name: methodSha256
          in: path
          required: true
          schema: { type: string, pattern: '^[a-f0-9]{64}$' }
      responses:
        '200':
          description: Exact immutable installation replayed
          headers:
            ETag: { schema: { type: string } }
            Location: { schema: { type: string } }
          content:
            application/json:
              schema: { type: object }
        '201':
          description: Immutable policy revision inserted
          headers:
            ETag: { schema: { type: string } }
            Location: { schema: { type: string } }
          content:
            application/json:
              schema: { type: object }
        '400': { $ref: '#/components/responses/Problem' }
        '401': { $ref: '#/components/responses/AuthenticationRequired' }
        '403': { $ref: '#/components/responses/InsufficientRole' }
        '404': { $ref: '#/components/responses/Problem' }
        '409': { $ref: '#/components/responses/Problem' }
        '429': { $ref: '#/components/responses/RateLimited' }
        '503': { $ref: '#/components/responses/Problem' }
'''
text = text.replace(marker, '\n' + block + marker, 1)
path.write_text(text)
print('Combined OpenAPI risk method selection routes: PATCHED')
