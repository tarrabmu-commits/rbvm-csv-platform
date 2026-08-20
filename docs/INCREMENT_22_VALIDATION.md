# Increment 22 Validation

Increment 22 integrates explicitly linked customer-managed asset context into the Decision Input boundary by introducing `RBVM_DECISION_INPUT_SNAPSHOT_V2` and PostgreSQL schema version 20.

## Required invariants

Validation must prove all of the following:

- historical `RBVM_DECISION_INPUT_SNAPSHOT_V1` canonical payload/hash behavior remains unchanged;
- V2 references contain an explicit `NativeEvidenceKind`;
- native identity is type + UUID rather than UUID alone;
- `MANAGED_ASSET_REVISION` requires an exact V21 scanner-managed-asset link binding;
- a V13 Asset Context row and a managed-asset revision remain independent even when they use the same UUID and semantic source string;
- methodology source allowlists remain filters and do not become source precedence;
- multiple admissible Asset Context native sources remain `AMBIGUOUS`;
- managed context is selected from immutable link/revision history as of `evaluatedAt`;
- the builder does not use `current_*` or `active_*` convenience views for managed-context selection;
- the resolver dereferences the exact native kind and UUID, verifies evidence provenance, verifies link-event provenance, and verifies the link belongs to the snapshot Finding scanner asset;
- V2 persistence requires schema version 20, while schema 17–19 continues to support V1;
- no Formula, Risk, Priority, SLA, treatment, or Case roll-up is introduced.

## Automated checks

`RbvmDecisionInputSnapshotV2SelfTest` exercises V2 contract invariants, including the same-source/same-UUID cross-native-store ambiguity case and V1 rejection of managed-asset typed references.

`PostgresMigratorSelfTest` verifies the migration sequence advances to schema version 20 and remains replay-safe.

Existing Decision Input builder, store, resolver, materializer, and runtime self-tests remain active to protect V1 compatibility.

`scripts/verify-decision-input-v2.py` provides structural checks across the V2 contract, generic selector, PostgreSQL builder/store/resolver, and migration. It explicitly rejects current managed-asset/link convenience views in the V22 builder.

The repository acceptance command remains:

```text
./scripts/verify.sh
```

Release acceptance also requires:

```text
./scripts/verify-release-version.sh v0.22.0
./scripts/verify-reproducible-build.sh
```

GitHub pull-request validation must finish with the repository `verify` and `codeql` workflows successful on the final V22 head.
