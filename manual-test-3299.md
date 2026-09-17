# Manual test: import-only provider profiles (#3299)

Branch: `fix-3299/profiles-import-only`

Verifies by hand what the automated suites cannot: that a **freshly installed
gateway serves an empty profile catalog**, that provider creation **fails closed**
with an actionable message until a profile is imported, and that everything works
normally once it is.

> This file is a scratch guide for reviewing the branch. It is not part of the
> change and should not be committed.

## 0. Prerequisites

- Rust toolchain (`rustup`), `mise`
- Podman running (`podman machine start`) — or Docker
- macOS only: z3 headers/libs, or the gateway build fails twice

  ```shell
  brew install z3
  export BINDGEN_EXTRA_CLANG_ARGS="-I/opt/homebrew/include"
  export LIBRARY_PATH="/opt/homebrew/lib"
  ```

- Memory is the practical limit here. Cap parallelism if the machine is small:

  ```shell
  export CARGO_BUILD_JOBS=2
  ```

## 1. Build

```shell
cargo build -p openshell-gateway --bin openshell-gateway
cargo build -p openshell-cli
```

```shell
export GATEWAY_BIN="$PWD/target/debug/openshell-gateway"
export OPENSHELL_BIN="$PWD/target/debug/openshell"
alias osh="$OPENSHELL_BIN"
```

## 2. Start a gateway with empty state

A new database is the point — this must be a gateway that has never had a profile
imported.

```shell
export OSH_TEST_DIR="$(mktemp -d)"
export XDG_CONFIG_HOME="${OSH_TEST_DIR}/config"     # keep your real CLI config untouched
mkdir -p "$XDG_CONFIG_HOME"

"$GATEWAY_BIN" \
  --bind-address 127.0.0.1 \
  --port 17670 \
  --health-port 17671 \
  --db-url "sqlite:${OSH_TEST_DIR}/gateway.db?mode=rwc" \
  --log-level info \
  > "${OSH_TEST_DIR}/gateway.log" 2>&1 &
echo $! > "${OSH_TEST_DIR}/gateway.pid"
```

Wait for health, then register the endpoint with the CLI:

```shell
until curl -sf http://127.0.0.1:17671/healthz >/dev/null; do sleep 1; done
echo "gateway healthy"

osh gateway add http://127.0.0.1:17670 --name manual-test --local
osh gateway list
```

**Check:** the gateway reached ready with no profiles configured. Before this
change the `builtin` source was non-empty by construction; an empty catalog is now
a valid start state.

## 3. The catalog is empty

```shell
osh provider list-profiles
```

**Expect:** `No provider profiles found.` — exit code 0, **not** an error.

```shell
osh provider list-profiles -o json     # expect: []
echo "exit=$?"
```

## 4. Provider creation fails closed

```shell
osh provider create --name gh --type github --credential GITHUB_TOKEN=dummy
```

**Expect:** failure naming the missing profile and the import command, e.g.
`provider profile 'github' was not found in the requested scope; import a matching
profile before creating this provider`.

Retired aliases must not resolve either:

```shell
osh provider create --name c --type claude  --credential ANTHROPIC_API_KEY=dummy   # expect failure
osh provider create --name g --type gh      --credential GITHUB_TOKEN=dummy        # expect failure
```

**Expect:** both fail. `claude` and `gh` are no longer aliases — use `claude-code`
and `github`.

## 5. Import the example profiles

Lint first, then import at platform scope:

```shell
osh provider profile lint --from providers
osh provider profile import --from providers --global
```

**Expect:** `Imported 15 provider profiles.`

```shell
osh provider list-profiles
```

**Expect:** all 15 at their canonical IDs (`github`, `pypi`, `anthropic`, …),
each with `source: user` and `scope: platform` — **not** `builtin`.

Confirm nothing is shadowed behind an imported profile:

```shell
osh provider profile export github -o yaml --global | head -20
```

**Expect:** `source: user`, `scope: platform`. Before this change a same-ID import
left the shipped definition resident as a `static_fallback`.

## 6. Provider creation now succeeds

```shell
osh provider create --name gh --type github --credential GITHUB_TOKEN=dummy
osh provider list
```

## 7. Catalog-driven credential suggestions

```shell
osh sandbox create --name warn-check --from base --env GITHUB_TOKEN=dummy -- true
```

**Expect:** the `--env` warning suggests `--type github`, sourced from the
gateway's catalog rather than a table compiled into the CLI. Delete a profile and
re-run to see the suggestion disappear:

```shell
osh provider profile delete pypi --global
osh sandbox create --name warn-check-2 --from base --env PYPI_TOKEN=dummy -- true
osh provider profile import -f providers/pypi.yaml --global   # restore
```

## 8. No provider is derived from the command

```shell
osh sandbox create --name no-infer --from base -- claude --version
```

**Expect:** no provider attached, no prompt. The trailing command never selects
a provider.

```shell
osh sandbox create --name infer-bash --from base -- bash -lc true
osh sandbox create --name infer-curl --from base -- curl --version
```

**Expect:** the same — nothing attached. `aws-s3` declares `/bin/bash` and six
profiles declare `curl`, but `binaries` authorizes a binary to reach a
profile's endpoints; it is not a request to attach that provider.

Naming one still works, and creates it when missing:

```shell
osh sandbox create --name explicit --from base --provider claude-code -- claude --version
```

## 9. Sandbox with a provider attached

```shell
osh sandbox create --name s1 --from base --provider gh -- bash -lc 'env | grep -c GITHUB_TOKEN'
osh sandbox provider list s1
```

## 10. Absent profile fails closed at composition

The new pre-flight in `CreateSandbox` / `AttachSandboxProvider`:

```shell
osh provider profile delete github --global      # provider 'gh' still refers to it
osh sandbox create --name s2 --from base --provider gh -- true
```

**Expect:** `FailedPrecondition` naming the provider, the missing profile ID, and
the import command.

Read paths must still work, so the provider stays recoverable:

```shell
osh provider list          # 'gh' still listed
osh provider get gh        # still readable
osh provider profile import -f providers/github.yaml --global   # recover
osh sandbox create --name s2 --from base --provider gh -- true  # now succeeds
```

## 11. The removed `builtin` config source is rejected

```shell
cat > "${OSH_TEST_DIR}/bad.toml" <<'TOML'
[openshell.gateway]
provider_profile_sources = [
  { type = "builtin" },
  { type = "user" },
]
TOML

"$GATEWAY_BIN" --config "${OSH_TEST_DIR}/bad.toml" \
  --db-url "sqlite:${OSH_TEST_DIR}/gateway.db?mode=rwc"
```

**Expect:** startup fails with a message saying `builtin` was removed and pointing
at `openshell provider profile import`, **not** an opaque "unknown variant" error.

## 12. Cleanup

```shell
kill "$(cat "${OSH_TEST_DIR}/gateway.pid")" 2>/dev/null
osh sandbox delete s1 s2 2>/dev/null
rm -rf "$OSH_TEST_DIR"
unset OSH_TEST_DIR XDG_CONFIG_HOME GATEWAY_BIN OPENSHELL_BIN
```

Open a fresh shell afterwards — `XDG_CONFIG_HOME` was overridden for the session.

## Known gaps

- Steps 7-10 need a working compute driver. With Podman, ensure
  `podman machine start` and that the base sandbox image pulls.
- Step 11 reuses the same database; that is fine because it fails before touching
  state, but use a fresh `--db-url` if you want to be strict.
- Nothing here exercises `aws-s3` — no automated lane does either, and the AWS CLI
  is absent from the community base image.
