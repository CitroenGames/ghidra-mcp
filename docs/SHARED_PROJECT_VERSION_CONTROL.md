# Shared-Project Version Control

The GUI plugin and standalone headless server expose the same guarded MCP
workflow for a file in an **open shared Ghidra project**:

1. `project_file_status` — inspect lifecycle state without changing it.
2. `checkout_program` — acquire a checkout only when the local file is current.
3. Use the normal analysis and write tools.
4. `checkin_program` — save, publish a new repository version, and verify it.

This path replaces Project window and Check In dialog automation for the normal
latest-version workflow. It does not guess how to resolve a merge conflict.

## Preflight

Inspect the current program:

```json
{
  "tool": "project_file_status",
  "arguments": {}
}
```

Or identify a project file explicitly:

```json
{
  "tool": "project_file_status",
  "arguments": { "path": "/BlackOps.exe" }
}
```

Important fields are:

- `version`, `latest_version`, and `version_delta`
- `is_latest_version`
- `is_checked_out`, `checkout_user`, `checkout_id`, and `checkout_version`
- `checkout_version_delta` and `checkout_is_latest`
- `active_checkout_count`, `active_checkouts`, and `checked_out_elsewhere`
- `is_changed` for unsaved database changes
- `modified_since_checkout` for saved local changes not yet published
- `blockers` and `next_action`

Do not edit when `is_latest_version` is false. If a checkout belongs to another
computer, release it from that computer; do not terminate or hijack it merely
to make automation proceed.

## Checkout

First perform a dry-run using the `latest_version` returned by preflight:

```json
{
  "tool": "checkout_program",
  "arguments": {
    "path": "/BlackOps.exe",
    "exclusive": true,
    "expected_latest_version": 121,
    "dry_run": true
  }
}
```

If the result is `ready_to_checkout`, repeat with `dry_run: false`. A successful
mutation returns `status: "checked_out"`, `verified: true`, and a complete
post-operation `file_status`. Calling the tool on this project's existing
checkout is an idempotent success (`already_checked_out`).

## Save and Check In

Re-run `project_file_status` after the batch. For a normal completed slice:

- `is_checked_out` and `is_latest_version` are true;
- `is_changed` may be true before save;
- `modified_since_checkout` becomes true once changes are saved;
- the checkout id and versions still match the values being guarded.

Dry-run the publication first:

```json
{
  "tool": "checkin_program",
  "arguments": {
    "path": "/BlackOps.exe",
    "comment": "c5s166: review 20 functions",
    "keep_checked_out": true,
    "allow_no_changes": false,
    "expected_version": 121,
    "expected_latest_version": 121,
    "expected_checkout_id": 42,
    "dry_run": true
  }
}
```

Use the actual values from `project_file_status`; the numbers above are only an
example. If the result is `ready_to_checkin`, repeat with `dry_run: false`.

The mutation:

1. validates the version and checkout compare-and-set guards;
2. requires a non-empty comment;
3. refuses a stale checkout or accidental no-change version;
4. saves pending database changes;
5. rechecks the guards because another user could publish during the save;
6. checks in through `DomainFile.checkin`;
7. verifies the version bump, latest state, and requested checkout state.

Success is `status: "checked_in"`, `version_bumped: true`, and
`verified: true`. Retain `keep_checked_out: true` while a GUI CodeBrowser still
has the program open. Headless mode can close its program and use false when it
must release the checkout.

`allow_no_changes` defaults to false so retrying a completed request cannot
silently create another empty server version. Set it to true only when an empty
version is intentional.

## Stale Versions and Merges

`checkin_program` returns `error_code: "merge_required"` instead of publishing
against a stale base. Automatic conflict resolution is intentionally outside
this endpoint: source/database merges can require analyst judgment, and a tool
must not choose one side silently.

Resolve or review the merge in Ghidra, then call `project_file_status` again and
repeat the guarded dry-run. A non-conflicting campaign that keeps one writer
serial should not need UI interaction for checkout, save, or check-in.

## Common Blocks

| `error_code` | Meaning |
|---|---|
| `stale_precondition` | An expected version or checkout id changed; inspect status again. |
| `not_latest_version` | Update the local project file before checkout. |
| `merge_required` | A newer server version exists; merge deliberately before check-in. |
| `no_changes` | No local changes exist and empty versions are disabled. |
| `open_file_requires_keep_checkout` | Keep the checkout or close the program first. |
| `file_busy` | Wait for the active project operation to finish and retry preflight. |
| `checkout_verification_failed` | Checkout returned without the required latest checked-out state. |
| `checkin_verification_failed` | Check-in returned, but one or more postconditions failed; inspect status before retrying. |

The older `server_version_control_*` tools remain for compatibility. For an
open shared project, prefer `project_file_status`, `checkout_program`, and
`checkin_program`; they expose the lifecycle guards and verified post-state.
