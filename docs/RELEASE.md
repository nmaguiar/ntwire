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
