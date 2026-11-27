# Release readiness

Run the release gate from a clean checkout after reviewing the intended
version and generated release metadata:

```sh
ojob tasks.yaml op=release
```

It runs dependency and formatting checks, `go vet ./...`, the complete normal
and race suites, a bounded five-second smoke fuzz of every public-input fuzz
target, builds every command, and then runs the disposable Docker Compose E2E
scenario. Set `FUZZ_TIME=30s` (or another Go duration) to lengthen the fuzz
smoke; keep an unbounded fuzz campaign separate from a release gate.

The CI workflow independently enforces normal tests, race tests, the same
fuzz smoke, cross-platform command builds, native macOS GUI verification, and
the Docker E2E scenario. The local gate is the operator-facing counterpart,
not a replacement for required CI status checks.

For a performance change, attach the raw results and paired comparison from
the [performance harness](PERFORMANCE.md). Record the measured topology and
workload limits. The scheduled loopback workflow checks fixture operation on
a shared runner. Release throughput and latency claims need controlled runs.
Keep WSS queue sampling opt-in unless paired runs meet the documented
sampling margin. An inconclusive overhead result can still support baseline
comparisons with sampling disabled.

For the [Phase 0 handoff](PERFORMANCE-BASELINE.md), retain one set of raw and
paired baseline reports for direct networking, native WireGuard, native and
alternate ntwire UDP, WSS, relay UDP, and multipath. Include proxy setup,
single-flow and loaded goodput, concurrent flows, and an isolated recovery run.
Record which modes were exercised only as functional smoke tests. For Phase 1,
compare each optimization against these fixture settings with diagnostic
sampling off unless the comparison specifically needs queue data. Record any
platform or hardware limits alongside the results.

Build release artifacts with a patched Go toolchain. Go 1.27.4 fixes the
standard-library HTTP/1 issue reported by the binary scan for Go 1.27.3.
Run the release scan on the same toolchain and binaries intended for
distribution. [Go vulnerability report](https://pkg.go.dev/vuln/GO-2026-6859)

Verify `LICENSE-QUIC-GO` is included in archives, images, and the
macOS app bundle. Refresh it from the pinned module when upgrading
quic-go and record the revision reviewed in the dependency sign-off.
[quic-go v0.66.0 license](https://github.com/quic-go/quic-go/blob/v0.66.0/LICENSE)

Adaptive negotiation is offered by default over verified HTTPS for
operator-enabled servers. Qualify a standard client against both an
adaptive and a legacy server, and test the explicit client rollback and a
denied adaptive upgrade. Qualify a stable lane across normal and interrupted carrier changes, exercise
reduced outer MTU with the Linux peer workflow, and verify previous
client and server binaries in both orders. Report QUIC reachability,
goodput, tail latency and client CPU separately. A reachability win does
not establish a performance gain on paths that already work.

Deploy the updated server before advertising the adaptive alternate
port. Disable new negotiation and reconnect clients on a legacy WireGuard
path before downgrading. Remove adaptive-only listener fields from the
configuration used by binaries that predate them. Keep the original
WireGuard keys and existing listener mappings through rollback.

## Sign-off record

Record each check with its command, commit, platform, result, and any useful
log/artifact link. Classify results precisely:

| Result | Meaning | Required follow-up |
| --- | --- | --- |
| Passed | The command completed successfully. | Record the command and platform. |
| Product failure | A build, assertion, race, fuzz finding, or E2E behavior failed. | Fix or explicitly defer before release. |
| Environment blocked | The check could not start or complete because of an external dependency, such as no Docker daemon, restricted loopback, unavailable credentials, or network/module outage. | Record the exact blocker and rerun in a suitable environment; do not call the check passed. |
| Not run | The check was intentionally skipped. | State why and obtain release-owner acceptance. |

Do not include private keys, bearer tokens, OIDC tokens, generated credentials,
or unredacted configuration in the record. Docker E2E diagnostics can contain
deployment detail; review them before attaching them to a ticket or release.

## Signed client update manifest

Provision `NTWIRE_UPDATE_SIGNING_KEY` (Actions secret) and
`NTWIRE_UPDATE_PUBLIC_KEY` (Actions variable) before enabling production client
updates. The final manifest job depends on all client archives, including the
native macOS GUI bundle; existing checksums remain unchanged. See
[UPDATES.md](UPDATES.md#release-signing-setup) for key generation, rotation and the
required per-OS manual acceptance checks. An unprovisioned release remains
installable through existing installers but unavailable to the self-updaters.
