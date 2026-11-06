# Dependency review

> **DRAFT.** Part of WS6. Re-run `npm audit` and re-check pinning before each release, not just
> once here.

## `npm audit`, 5 November 2026

```
0 vulnerabilities (0 info, 0 low, 0 moderate, 0 high, 0 critical)
113 prod dependencies, 1 dev
```

## Pinning

Per `PLAN.md` §4 (WS0): "the interceptor and executor interfaces are public API, not internals" -
`@a2a-js/sdk` and `@kya-os/mcp` MUST be pinned exactly, not range-pinned, since a minor upstream
release changing either SDK's behaviour under us would be silent. Checked across all three
packages:

| Package | Spec | Exact? |
|---|---|---|
| `@a2a-js/sdk` | `1.3.0` | Yes |
| `@kya-os/mcp` | `1.21.2` | Yes |
| `@sd-jwt/core` | `^0.24.3` | No - pre-1.0, range-pinned deliberately (see note) |
| `@grpc/grpc-js`, `@bufbuild/protobuf`, `express`, `jose`, `json-canonicalize` | range-pinned (`^`) | No - transport/utility libraries, not the trust-sensitive SDKs the pinning rule targets |

**Note on `@sd-jwt/core`:** pre-1.0 (`0.24.x`), so even a patch release can change behaviour under
semver's own rules. Range-pinned for now because no vendored lockstep process exists yet for a
fourth dependency; revisit this once it reaches 1.0, or pin it exactly too if an unreviewed minor
bump is judged too risky before then. Not currently treated as equivalent in risk to
`@a2a-js/sdk`/`@kya-os/mcp` since `packages/ap2`'s own code (not `@sd-jwt/core`'s internals) is
what interprets AP2's payload semantics - `@sd-jwt/core` is only the base SD-JWT/KB-JWT crypto
layer underneath it.

`jose` is pinned consistently at `^6.2.15` across `packages/a2a` and `packages/ap2` - no version
drift between the two.

## Not done

- No automated `npm audit`/Dependabot gate in CI yet - this review is a manual snapshot, not a
  standing check. Adding one is a release-pipeline change, deliberately not made in this pass
  (see `docs/security/threat-model.md`'s scope note on CI).
- No SBOM generated.

## License

[Apache 2.0](../../LICENSE)
