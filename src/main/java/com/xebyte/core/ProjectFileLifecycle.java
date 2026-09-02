package com.xebyte.core;

import ghidra.framework.model.DomainFile;
import ghidra.framework.store.ItemCheckoutStatus;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds a read-only, machine-actionable lifecycle snapshot for a project
 * {@link DomainFile}.  The raw {@code can*} values remain authoritative; the
 * blocker lists only explain observable state and never attempt an operation.
 */
public final class ProjectFileLifecycle {

    private ProjectFileLifecycle() {}

    public static Map<String, Object> inspect(DomainFile file) {
        Map<String, Object> out = new LinkedHashMap<>();

        boolean versioned = file.isVersioned();
        boolean checkedOut = file.isCheckedOut();
        boolean exclusive = file.isCheckedOutExclusive();
        boolean latest = file.isLatestVersion();
        boolean readOnly = file.isReadOnly();
        boolean busy = file.isBusy();
        boolean changed = file.isChanged();
        boolean modifiedSinceCheckout = file.modifiedSinceCheckout();
        boolean writableProject = file.isInWritableProject();
        boolean canSave = file.canSave();
        boolean canCheckout = file.canCheckout();
        boolean canCheckin = file.canCheckin();
        boolean canMerge = file.canMerge();
        boolean canAddToRepository = file.canAddToRepository();

        out.put("name", file.getName());
        out.put("path", file.getPathname());
        out.put("content_type", file.getContentType());
        int version = file.getVersion();
        int latestVersion = file.getLatestVersion();
        out.put("version", version);
        out.put("latest_version", latestVersion);
        out.put("version_delta", Math.max(0, latestVersion - version));
        out.put("is_latest_version", latest);
        out.put("is_versioned", versioned);
        out.put("is_checked_out", checkedOut);
        out.put("is_checked_out_exclusive", exclusive);
        out.put("is_read_only", readOnly);
        out.put("is_hijacked", file.isHijacked());
        out.put("is_open", file.isOpen());
        out.put("is_busy", busy);
        out.put("is_changed", changed);
        out.put("modified_since_checkout", modifiedSinceCheckout);
        out.put("is_in_writable_project", writableProject);
        out.put("can_save", canSave);
        out.put("can_checkout", canCheckout);
        out.put("can_checkin", canCheckin);
        out.put("can_merge", canMerge);
        out.put("can_add_to_repository", canAddToRepository);

        if (checkedOut) {
            try {
                ItemCheckoutStatus status = file.getCheckoutStatus();
                if (status != null) {
                    int checkoutVersion = status.getCheckoutVersion();
                    out.put("checkout_user", status.getUser());
                    out.put("checkout_id", status.getCheckoutId());
                    out.put("checkout_version", checkoutVersion);
                    out.put("checkout_version_delta",
                        Math.max(0, latestVersion - checkoutVersion));
                    out.put("checkout_is_latest",
                        latest && checkoutVersion == latestVersion);
                }
            } catch (IOException e) {
                out.put("checkout_status_error", safeMessage(e));
            }
        }

        if (versioned) {
            try {
                ItemCheckoutStatus[] statuses = file.getCheckouts();
                List<Map<String, Object>> activeCheckouts = new ArrayList<>();
                if (statuses != null) {
                    for (ItemCheckoutStatus status : statuses) {
                        if (status == null) continue;
                        Map<String, Object> checkout = new LinkedHashMap<>();
                        checkout.put("checkout_id", status.getCheckoutId());
                        checkout.put("user", status.getUser());
                        checkout.put("checkout_version", status.getCheckoutVersion());
                        checkout.put("checkout_type", String.valueOf(status.getCheckoutType()));
                        checkout.put("checkout_date", status.getCheckoutDate());
                        checkout.put("project_path", status.getProjectPath());
                        checkout.put("user_host", status.getUserHostName());
                        activeCheckouts.add(checkout);
                    }
                }
                out.put("active_checkout_count", activeCheckouts.size());
                out.put("active_checkouts", activeCheckouts);
                out.put("checked_out_elsewhere", !checkedOut && !activeCheckouts.isEmpty());
            } catch (IOException e) {
                out.put("active_checkouts_error", safeMessage(e));
            }
        }

        List<String> checkoutBlockers = checkoutBlockers(
            versioned, checkedOut, latest, readOnly, busy, canCheckout);
        List<String> checkinBlockers = checkinBlockers(
            versioned, checkedOut, latest, busy, canCheckin, canMerge);
        List<String> mergeBlockers = mergeBlockers(
            versioned, checkedOut, latest, busy, canMerge);
        List<String> editBlockers = editBlockers(
            versioned, checkedOut, latest, readOnly, busy, writableProject);
        List<String> saveBlockers = saveBlockers(editBlockers, canSave);
        List<String> addBlockers = addToRepositoryBlockers(
            versioned, readOnly, busy, writableProject, canAddToRepository);

        Map<String, Object> blockers = new LinkedHashMap<>();
        blockers.put("add_to_repository", addBlockers);
        blockers.put("checkout", checkoutBlockers);
        blockers.put("edit", editBlockers);
        blockers.put("save", saveBlockers);
        blockers.put("merge", mergeBlockers);
        blockers.put("checkin", checkinBlockers);
        out.put("blockers", blockers);
        out.put("next_action", nextAction(
            versioned, checkedOut, latest, changed, modifiedSinceCheckout,
            addBlockers, checkoutBlockers, editBlockers, saveBlockers,
            mergeBlockers, checkinBlockers));
        return out;
    }

    static List<String> checkoutBlockers(boolean versioned, boolean checkedOut,
            boolean latest, boolean readOnly, boolean busy, boolean canCheckout) {
        List<String> blockers = new ArrayList<>();
        if (!versioned) blockers.add("not_versioned");
        if (checkedOut) blockers.add("already_checked_out");
        if (versioned && !latest) blockers.add("not_latest_version");
        if (readOnly) blockers.add("read_only");
        if (busy) blockers.add("file_busy");
        if (blockers.isEmpty() && !canCheckout) blockers.add("domain_file_refused_checkout");
        return blockers;
    }

    static List<String> checkinBlockers(boolean versioned, boolean checkedOut,
            boolean latest, boolean busy, boolean canCheckin, boolean canMerge) {
        List<String> blockers = new ArrayList<>();
        if (!versioned) blockers.add("not_versioned");
        if (!checkedOut) blockers.add("not_checked_out");
        if (busy) blockers.add("file_busy");
        if (versioned && checkedOut && !latest) {
            blockers.add("not_latest_version");
            blockers.add(canMerge ? "merge_required" : "merge_unavailable");
        }
        if (blockers.isEmpty() && !canCheckin) blockers.add("domain_file_refused_checkin");
        return blockers;
    }

    static List<String> mergeBlockers(boolean versioned, boolean checkedOut,
            boolean latest, boolean busy, boolean canMerge) {
        List<String> blockers = new ArrayList<>();
        if (!versioned) blockers.add("not_versioned");
        if (!checkedOut) blockers.add("not_checked_out");
        if (versioned && checkedOut && latest) blockers.add("already_latest_version");
        if (busy) blockers.add("file_busy");
        if (blockers.isEmpty() && !canMerge) blockers.add("domain_file_refused_merge");
        return blockers;
    }

    static List<String> editBlockers(boolean versioned, boolean checkedOut,
            boolean latest, boolean readOnly, boolean busy, boolean writableProject) {
        List<String> blockers = new ArrayList<>();
        if (!writableProject) blockers.add("project_not_writable");
        if (versioned && !checkedOut) blockers.add("not_checked_out");
        if (versioned && !latest) blockers.add("not_latest_version");
        if (readOnly) blockers.add("read_only");
        if (busy) blockers.add("file_busy");
        return blockers;
    }

    static List<String> saveBlockers(List<String> editBlockers, boolean canSave) {
        List<String> blockers = new ArrayList<>(editBlockers);
        if (blockers.isEmpty() && !canSave) blockers.add("domain_file_refused_save");
        return blockers;
    }

    static List<String> addToRepositoryBlockers(boolean versioned, boolean readOnly,
            boolean busy, boolean writableProject, boolean canAddToRepository) {
        List<String> blockers = new ArrayList<>();
        if (versioned) blockers.add("already_versioned");
        if (!writableProject) blockers.add("project_not_writable");
        if (readOnly) blockers.add("read_only");
        if (busy) blockers.add("file_busy");
        if (blockers.isEmpty() && !canAddToRepository) {
            blockers.add("domain_file_refused_add_to_repository");
        }
        return blockers;
    }

    static String nextAction(boolean versioned, boolean checkedOut, boolean latest,
            boolean changed, boolean modifiedSinceCheckout,
            List<String> addBlockers, List<String> checkoutBlockers,
            List<String> editBlockers, List<String> saveBlockers,
            List<String> mergeBlockers, List<String> checkinBlockers) {
        if (!versioned) {
            return addBlockers.isEmpty()
                ? "add_to_version_control" : "resolve_add_to_repository_blockers";
        }
        if (!checkedOut) {
            return checkoutBlockers.isEmpty()
                ? "checkout" : "resolve_checkout_blockers";
        }
        if (!latest) {
            return mergeBlockers.isEmpty()
                ? "merge_latest" : "resolve_merge_blockers";
        }
        if (!editBlockers.isEmpty()) return "resolve_edit_blockers";
        if (changed) {
            return saveBlockers.isEmpty() ? "save" : "resolve_save_blockers";
        }
        if (checkinBlockers.isEmpty()) return "checkin";
        if (modifiedSinceCheckout) return "resolve_checkin_blockers";
        return "ready_for_edit";
    }

    private static String safeMessage(Exception e) {
        return e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
    }
}
