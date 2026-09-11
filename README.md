# Pulp-ext-process

`Pulp-ext-process` provides guarded host-process execution for Pulp
applications. Process spawning remains behind an explicit host capability
boundary.

## Scoped Git inspection

An exact host-owned `spawn.process` placement grant with resource
`git-inspect`, right `execute`, and absolute `executable` and `root` attributes
activates a narrow policy for that cell. Both paths are symlink-resolved and
canonicalized. Every request must use that exact executable and working root.
Only Git inspection subcommands are accepted; root-changing and configuration
injection options and unrecognized environment variables are denied.

The scoped grant takes precedence over `PROCESS_ALLOW_BINS` and
`PROCESS_RUN_ROOTS`. When the resolver is nil or has no exact grant, existing
legacy allowlist behavior remains unchanged.

## Fixed verification

The `fixed-verification` resource also requires `execute`, but admits only the
exact `argv_json` and `env_json` declared by the host. `executable` and `root`
are canonicalized exactly as above; `max_timeout_ms` and `max_output_bytes`
bound every invocation. The guest may request a smaller positive timeout but
cannot add arguments, change environment, select another root or executable,
disable timeout, or increase captured output.
Fixed verification replaces, rather than overlays, the child environment, so
undeclared ambient host variables are not inherited.

## Development

```sh
go test ./...
```

## License

MIT
