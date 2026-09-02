# Updating Ghidra MCP

This guide updates an existing source checkout and deploys the resulting Java
extension and Python bridge artifacts. A `git pull` by itself does **not**
update the extension already loaded by Ghidra.

The supported workflow is `python -m tools.setup`. Maven is the authoritative
build backend unless `TOOLS_SETUP_BACKEND=gradle` is deliberately configured.

## What Gets Updated

Ghidra MCP has three distinct pieces:

1. **Source checkout** — the Git repository containing Java, Python, tests, and
   documentation.
2. **Ghidra extension** — the built Java plugin installed in the Ghidra user
   profile, such as
   `%APPDATA%\ghidra\ghidra_<version>_PUBLIC\Extensions\GhidraMCP\` on
   Windows.
3. **Python MCP bridge** — the process launched by the MCP client. It may run
   from this checkout, a `uv` environment, or a separately installed wheel.

Updating one piece does not automatically refresh the other two. The deploy
command rebuilds and installs the Ghidra extension, builds and copies the bridge
wheel, restarts Ghidra, and verifies the live HTTP schema. Restart or reconnect
the MCP client afterward so it reloads the Python process and tool catalog.

Ghidra projects and shared-server repositories are separate from the plugin.
Deploying the extension does not replace or migrate project databases.

## Before You Deploy

1. Inspect the source worktree. Do not pull over uncommitted work you intend to
   keep.

   ```text
   git status --short --branch
   git remote -v
   ```

2. Finish active Ghidra work. Save local changes and, for a shared repository,
   check completed work into the Ghidra Server before updating the plugin.

   `tools.setup deploy` asks a matching Ghidra instance to save open programs
   and exit. If it cannot exit within the timeout, it may terminate that
   matching process. Its automatic save is **not** a shared-repository
   check-in. Use the guarded workflow in
   [`SHARED_PROJECT_VERSION_CONTROL.md`](SHARED_PROJECT_VERSION_CONTROL.md) to
   preflight and publish the file through MCP before deployment.

3. Close unrelated Ghidra installations that might also bind the configured
   MCP port (normally `127.0.0.1:8089`). The deploy command warns about them but
   does not close them.

4. Confirm the intended Ghidra installation path. Pass it explicitly or set
   `GHIDRA_PATH` in the Git-ignored `.env` file.

   ```text
   GHIDRA_PATH=C:\Tools\ghidra_12.1.2_PUBLIC
   ```

   Start from `.env.template` when creating a new `.env`. Keep authentication
   tokens and shared-server passwords out of Git.

## Routine Update

Run these commands from the repository root. Replace the Ghidra path with the
installation you actually use.

### 1. Update the source checkout

If the update is already present as local source changes, skip this step.
Otherwise fetch from the remote you intentionally configured and require a
fast-forward update:

```text
git fetch --all --prune
git pull --ff-only
git status --short --branch
```

Review release notes and `CHANGELOG.md` before deploying across a major version
or changing Ghidra versions.

### 2. Validate prerequisites

```text
python -m tools.setup preflight --ghidra-path "C:\Tools\ghidra_12.1.2_PUBLIC"
```

Run `ensure-prereqs` on the first build, after dependency changes, or after
installing a different Ghidra version:

```text
python -m tools.setup ensure-prereqs --ghidra-path "C:\Tools\ghidra_12.1.2_PUBLIC"
```

If the Ghidra installation changed and Maven still has JARs from the previous
version, reinstall them deliberately:

```text
python -m tools.setup ensure-prereqs --force --ghidra-path "C:\Tools\ghidra_12.1.2_PUBLIC"
```

### 3. Run offline tests

```text
python -m tools.setup run-tests
pytest tests/unit/ -v --no-cov
```

The first command runs the offline Java suite. The second runs the Python unit
suite. Fix failures before installing the new extension.

### 4. Build

```text
python -m tools.setup build
```

The Maven build writes the plugin JAR and extension archive under `target/`.
Do not manually combine artifacts from different builds or versions.

### 5. Preview deployment

```text
python -m tools.setup deploy --dry-run --ghidra-path "C:\Tools\ghidra_12.1.2_PUBLIC"
```

Review the source archive, target installation, user-profile extension path,
Ghidra process handling, and configured project before executing the deploy.

### 6. Deploy

```text
python -m tools.setup deploy --ghidra-path "C:\Tools\ghidra_12.1.2_PUBLIC"
```

The deploy command:

- saves and closes a running Ghidra process from the matching installation;
- removes stale `GhidraMCP*.zip` and user-profile `GhidraMCP*.jar` artifacts;
- installs the newly built extension archive and user-profile extension;
- builds and copies the Python bridge wheel;
- copies the local `.env` into the Ghidra installation when one exists;
- patches the Ghidra user tool configuration;
- starts Ghidra and waits for MCP health and an active project; and
- runs the default live health/schema smoke checks.

A plain deploy does not import benchmark programs. Release and benchmark test
tiers are opt-in; see [Testing](TESTING.md).

### 7. Restart or reconnect the MCP client

MCP clients can cache the Python bridge process and the tool catalog. After a
Java endpoint or Python bridge change, restart the configured MCP server or
reconnect the client. A new client session may be required to see newly added
tools.

If the client runs the bridge from this checkout, refresh its environment when
Python dependencies changed:

```text
python -m tools.setup install-python-deps
```

If the client points to a separately installed wheel, reinstall the wheel in
that client's Python environment instead. Copying a wheel into the Ghidra
installation does not update an unrelated virtual environment by itself.

## Verify the Live Update

Successful deployment already checks health and schema. These extra checks are
useful when validating a specific endpoint or diagnosing a stale client.

### HTTP health and schema on Windows PowerShell

```powershell
$mcpUrl = "http://127.0.0.1:8089"
Invoke-RestMethod "$mcpUrl/mcp/health"
$schema = Invoke-RestMethod "$mcpUrl/mcp/schema"
$schema.tools.Count

# Replace example_tool with the endpoint changed by the update.
$schema.tools | Where-Object {
    $_.name -eq "example_tool" -or $_.path -eq "/example_tool"
}
```

Verify the changed endpoint itself with a bounded read-only request before
using it for project mutations.

### Confirm the installed Java artifact on Windows

```powershell
$installed = Get-ChildItem `
    "$env:APPDATA\ghidra\ghidra_*_PUBLIC\Extensions\GhidraMCP\lib\GhidraMCP*.jar" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

$installed | Select-Object FullName, Length, LastWriteTime
Get-FileHash $installed.FullName -Algorithm SHA256
```

The installed extension comes from the user profile above, not from the
repository's `.git` directory. Reinitializing Git does not change the installed
plugin; only a build and deploy does.

## Which Steps Does My Change Need?

| Change | Build Java | Deploy/restart Ghidra | Restart MCP client |
|---|---:|---:|---:|
| Documentation only | No | No | No |
| Java endpoint or service | Yes | Yes | Yes, to refresh tools |
| Endpoint catalog/schema | Yes | Yes | Yes |
| Python bridge code | Usually no | Only if Java also changed | Yes |
| Python dependencies | No | No | Yes, after dependency sync |
| Ghidra version change | Yes | Yes, after forced prerequisites | Yes |

## Troubleshooting

### The old tool list is still visible

- Confirm `/mcp/schema` contains the expected tool.
- Restart or reconnect the MCP client; it may have cached `tools/list`.
- Confirm the client is connected to the expected Ghidra instance and port.

### The installed JAR cannot be replaced

Ghidra is probably still holding it open. Save and check in project work, close
all processes from the target installation, and rerun deploy. Do not copy a new
JAR beside the old one; deploy intentionally removes stale matching JARs.

### Deploy reports the wrong version or schema

Another Ghidra installation may be serving port 8089. Close it, verify the
target path, and redeploy. The deploy command prints mismatched Ghidra process
IDs when it detects them.

### Preflight or compilation cannot find Ghidra classes

Reinstall the target installation's Maven dependencies:

```text
python -m tools.setup install-ghidra-deps --force --ghidra-path "C:\Tools\ghidra_12.1.2_PUBLIC"
```

Then rerun preflight, tests, and build.

### Roll back a bad update

Return the source checkout to a known-good commit in a clean worktree, rebuild,
and deploy that version through the same workflow. Do not restore only the JAR
while leaving a newer bridge/schema in place; roll back the Java and Python
pieces together, then verify the live schema again.
