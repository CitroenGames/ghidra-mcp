package com.xebyte.core;

import ghidra.framework.data.CheckinHandler;
import ghidra.framework.model.DomainFile;
import ghidra.framework.store.ItemCheckoutStatus;
import ghidra.util.task.TaskMonitor;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Guarded, machine-actionable version-control operations for an open-project
 * {@link DomainFile}.  These operations deliberately use the project file API;
 * the repository adapter cannot save or check in a local program database.
 */
public final class ProjectFileVersionControl {

    /** Saves pending local database changes before a check-in. */
    @FunctionalInterface
    public interface SaveOperation {
        void save(DomainFile file, String comment, TaskMonitor monitor) throws Exception;
    }

    private ProjectFileVersionControl() {}

    public static Map<String, Object> checkout(DomainFile file, boolean exclusive,
            int expectedLatestVersion, boolean dryRun, TaskMonitor monitor) {
        Map<String, Object> before = ProjectFileLifecycle.inspect(file);
        Map<String, Object> out = baseResult("checkout", dryRun, before);

        String guardError = validateExpectedVersions(
            file, -1, expectedLatestVersion, -1L);
        if (guardError != null) {
            return fail(out, "stale_precondition", guardError, file);
        }
        if (!file.isVersioned()) {
            return fail(out, "not_versioned", "File is not under version control", file);
        }
        if (!file.isLatestVersion()) {
            return fail(out, file.isCheckedOut() ? "merge_required" : "not_latest_version",
                file.isCheckedOut()
                    ? "Existing checkout is not based on the latest repository version; update or merge it before editing"
                    : "Local project file is not at the latest repository version; update it before checkout",
                file);
        }
        if (file.isCheckedOut()) {
            out.put("success", true);
            out.put("status", "already_checked_out");
            out.put("idempotent", true);
            out.put("file_status", ProjectFileLifecycle.inspect(file));
            return out;
        }
        if (file.isReadOnly()) {
            return fail(out, "read_only", "File is read-only", file);
        }
        if (!file.isInWritableProject()) {
            return fail(out, "project_not_writable", "Project is not writable", file);
        }
        if (file.isBusy()) {
            return fail(out, "file_busy", "File is busy", file);
        }
        if (!file.canCheckout()) {
            return fail(out, "checkout_refused",
                "DomainFile reports that checkout is not currently available", file);
        }

        if (dryRun) {
            out.put("success", true);
            out.put("status", "ready_to_checkout");
            out.put("exclusive", exclusive);
            out.put("file_status", before);
            return out;
        }

        try {
            boolean accepted = file.checkout(exclusive, monitor);
            Map<String, Object> after = ProjectFileLifecycle.inspect(file);
            boolean verified = accepted && file.isCheckedOut() && file.isLatestVersion();
            out.put("success", verified);
            out.put("status", verified ? "checked_out" : "checkout_verification_failed");
            out.put("exclusive", exclusive);
            out.put("checkout_accepted", accepted);
            out.put("verified", verified);
            out.put("file_status", after);
            if (!verified) {
                out.put("error_code", "checkout_verification_failed");
                out.put("error", "Checkout did not produce a latest checked-out project file");
            }
            return out;
        } catch (Exception e) {
            return fail(out, "checkout_failed", "Checkout failed: " + safeMessage(e), file);
        }
    }

    public static Map<String, Object> checkin(DomainFile file, String comment,
            boolean keepCheckedOut, boolean allowNoChanges, int expectedVersion,
            int expectedLatestVersion, long expectedCheckoutId, boolean dryRun,
            TaskMonitor monitor, SaveOperation saveOperation) {
        Map<String, Object> before = ProjectFileLifecycle.inspect(file);
        Map<String, Object> out = baseResult("checkin", dryRun, before);
        String normalizedComment = comment == null ? "" : comment.trim();

        if (normalizedComment.isEmpty()) {
            return fail(out, "comment_required",
                "A non-empty check-in comment is required", file);
        }
        String guardError = validateExpectedVersions(
            file, expectedVersion, expectedLatestVersion, expectedCheckoutId);
        if (guardError != null) {
            return fail(out, "stale_precondition", guardError, file);
        }
        if (!file.isVersioned()) {
            return fail(out, "not_versioned", "File is not under version control", file);
        }
        if (!file.isCheckedOut()) {
            return fail(out, "not_checked_out", "File is not checked out in this project", file);
        }
        if (!file.isLatestVersion()) {
            return fail(out, "merge_required",
                "Checkout is not based on the latest repository version; update or merge before check-in",
                file);
        }
        if (file.isBusy()) {
            return fail(out, "file_busy", "File is busy", file);
        }
        if (!keepCheckedOut && file.isOpen()) {
            return fail(out, "open_file_requires_keep_checkout",
                "An open file cannot reliably drop its checkout; close it first or set keep_checked_out=true",
                file);
        }
        boolean hasChanges = file.isChanged() || file.modifiedSinceCheckout();
        if (!allowNoChanges && !hasChanges) {
            return fail(out, "no_changes",
                "No unsaved or saved changes exist since checkout; refusing an empty repository version",
                file);
        }
        // Unsaved DomainFile changes commonly make canCheckin() false until
        // save completes.  Do not reject that normal state before running the
        // endpoint's save step; the authoritative check is repeated below.
        if (!file.isChanged() && !file.canCheckin()) {
            return fail(out, "checkin_refused",
                "DomainFile reports that check-in is not currently available", file);
        }

        boolean wouldSave = file.isChanged();
        out.put("comment", normalizedComment);
        out.put("keep_checked_out", keepCheckedOut);
        out.put("allow_no_changes", allowNoChanges);
        out.put("would_save", wouldSave);
        if (dryRun) {
            out.put("success", true);
            out.put("status", "ready_to_checkin");
            out.put("file_status", before);
            return out;
        }

        boolean saved = false;
        try {
            if (wouldSave) {
                saveOperation.save(file, normalizedComment, monitor);
                saved = true;
                if (file.isChanged()) {
                    out.put("saved", true);
                    return fail(out, "save_verification_failed",
                        "Save returned but the project file still reports unsaved changes", file);
                }
            }

            // Re-run every concurrency-sensitive guard after the save. Another
            // user may have published a new server version while saving.
            String postSaveGuard = validateExpectedVersions(
                file, expectedVersion, expectedLatestVersion, expectedCheckoutId);
            if (postSaveGuard != null) {
                out.put("saved", saved);
                return fail(out, "stale_precondition", postSaveGuard, file);
            }
            if (!file.isCheckedOut()) {
                out.put("saved", saved);
                return fail(out, "checkout_changed_during_save",
                    "Checkout disappeared while saving", file);
            }
            if (!file.isLatestVersion()) {
                out.put("saved", saved);
                return fail(out, "merge_required",
                    "A newer repository version appeared while saving; merge before check-in", file);
            }
            if (!file.canCheckin()) {
                out.put("saved", saved);
                return fail(out, "checkin_refused",
                    "DomainFile refused check-in after save", file);
            }

            int versionBefore = file.getVersion();
            final String finalComment = normalizedComment;
            final boolean finalKeepCheckedOut = keepCheckedOut;
            file.checkin(new CheckinHandler() {
                @Override
                public boolean keepCheckedOut() { return finalKeepCheckedOut; }

                @Override
                public String getComment() { return finalComment; }

                @Override
                public boolean createKeepFile() { return false; }
            }, monitor);

            int versionAfter = file.getVersion();
            boolean checkoutStateVerified = keepCheckedOut
                ? file.isCheckedOut() : !file.isCheckedOut();
            boolean verified = versionAfter > versionBefore
                && file.isLatestVersion() && checkoutStateVerified;

            out.put("success", verified);
            out.put("status", verified ? "checked_in" : "checked_in_but_verification_failed");
            out.put("saved", saved);
            out.put("version_before", versionBefore);
            out.put("version", versionAfter);
            out.put("version_bumped", versionAfter > versionBefore);
            out.put("verified", verified);
            out.put("file_status", ProjectFileLifecycle.inspect(file));
            if (!verified) {
                out.put("error_code", "checkin_verification_failed");
                out.put("error",
                    "Check-in returned but version/latest/checkout postconditions were not all satisfied");
            }
            return out;
        } catch (Exception e) {
            out.put("saved", saved);
            return fail(out, "checkin_failed", "Check-in failed: " + safeMessage(e), file);
        }
    }

    private static String validateExpectedVersions(DomainFile file, int expectedVersion,
            int expectedLatestVersion, long expectedCheckoutId) {
        if (expectedVersion >= 0 && file.getVersion() != expectedVersion) {
            return "Expected local version " + expectedVersion + " but found " + file.getVersion();
        }
        if (expectedLatestVersion >= 0 && file.getLatestVersion() != expectedLatestVersion) {
            return "Expected latest repository version " + expectedLatestVersion
                + " but found " + file.getLatestVersion();
        }
        if (expectedCheckoutId >= 0) {
            try {
                ItemCheckoutStatus status = file.getCheckoutStatus();
                if (status == null) {
                    return "Expected checkout id " + expectedCheckoutId + " but no local checkout exists";
                }
                if (status.getCheckoutId() != expectedCheckoutId) {
                    return "Expected checkout id " + expectedCheckoutId
                        + " but found " + status.getCheckoutId();
                }
            } catch (Exception e) {
                return "Could not verify expected checkout id: " + safeMessage(e);
            }
        }
        return null;
    }

    private static Map<String, Object> baseResult(String operation, boolean dryRun,
            Map<String, Object> before) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("operation", operation);
        out.put("dry_run", dryRun);
        out.put("file_status_before", before);
        return out;
    }

    private static Map<String, Object> fail(Map<String, Object> out, String code,
            String message, DomainFile file) {
        out.put("success", false);
        out.put("status", "blocked");
        out.put("error_code", code);
        out.put("error", message);
        out.put("file_status", ProjectFileLifecycle.inspect(file));
        return out;
    }

    private static String safeMessage(Exception e) {
        return e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
    }
}
