package com.xebyte.offline;

import com.xebyte.core.ProjectFileLifecycle;
import com.xebyte.headless.HeadlessProgramProvider;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.store.ItemCheckoutStatus;
import junit.framework.TestCase;

import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Offline contract tests for the read-only DomainFile lifecycle preflight. */
public class ProjectFileLifecycleTest extends TestCase {

    public void testCheckedOutStaleFileReportsOwnerAndMergeRequirement() throws Exception {
        DomainFile file = baseFile();
        ItemCheckoutStatus checkout = mock(ItemCheckoutStatus.class);
        when(file.isCheckedOut()).thenReturn(true);
        when(file.isCheckedOutExclusive()).thenReturn(true);
        when(file.isLatestVersion()).thenReturn(false);
        when(file.canCheckout()).thenReturn(false);
        when(file.canCheckin()).thenReturn(false);
        when(file.canMerge()).thenReturn(true);
        when(file.modifiedSinceCheckout()).thenReturn(true);
        when(file.getCheckoutStatus()).thenReturn(checkout);
        when(checkout.getUser()).thenReturn("analyst");
        when(checkout.getCheckoutId()).thenReturn(42L);
        when(checkout.getCheckoutVersion()).thenReturn(7);

        Map<String, Object> status = ProjectFileLifecycle.inspect(file);

        assertEquals(false, status.get("is_latest_version"));
        assertEquals(true, status.get("can_merge"));
        assertEquals("analyst", status.get("checkout_user"));
        assertEquals(42L, status.get("checkout_id"));
        assertEquals(7, status.get("checkout_version"));
        assertEquals(1, status.get("version_delta"));
        assertEquals(1, status.get("checkout_version_delta"));
        assertEquals(false, status.get("checkout_is_latest"));
        assertEquals("merge_latest", status.get("next_action"));

        Map<?, ?> blockers = (Map<?, ?>) status.get("blockers");
        assertTrue(((List<?>) blockers.get("checkin")).contains("merge_required"));
        assertTrue(((List<?>) blockers.get("checkout")).contains("already_checked_out"));
        assertTrue(((List<?>) blockers.get("edit")).contains("not_latest_version"));
    }

    public void testLatestUnchangedCheckoutIsReadyToCheckIn() throws Exception {
        DomainFile file = baseFile();
        when(file.isCheckedOut()).thenReturn(true);
        when(file.isLatestVersion()).thenReturn(true);
        when(file.canCheckin()).thenReturn(true);

        Map<String, Object> status = ProjectFileLifecycle.inspect(file);

        assertEquals("checkin", status.get("next_action"));
        Map<?, ?> blockers = (Map<?, ?>) status.get("blockers");
        assertEquals(List.of(), blockers.get("checkin"));
        assertEquals(List.of(), blockers.get("edit"));
    }

    public void testSavedCheckoutChangesLeadToCheckinRatherThanAnotherSave() throws Exception {
        DomainFile file = baseFile();
        when(file.isCheckedOut()).thenReturn(true);
        when(file.isLatestVersion()).thenReturn(true);
        when(file.isChanged()).thenReturn(false);
        when(file.modifiedSinceCheckout()).thenReturn(true);
        when(file.canCheckin()).thenReturn(true);

        Map<String, Object> status = ProjectFileLifecycle.inspect(file);

        assertEquals("checkin", status.get("next_action"));
    }

    public void testBusyFileNeverRecommendsCheckinEvenIfCanCheckinIsTrue() throws Exception {
        DomainFile file = baseFile();
        when(file.isCheckedOut()).thenReturn(true);
        when(file.isBusy()).thenReturn(true);
        when(file.canCheckin()).thenReturn(true);

        Map<String, Object> status = ProjectFileLifecycle.inspect(file);

        assertEquals("resolve_edit_blockers", status.get("next_action"));
        Map<?, ?> blockers = (Map<?, ?>) status.get("blockers");
        assertTrue(((List<?>) blockers.get("checkin")).contains("file_busy"));
        assertTrue(((List<?>) blockers.get("edit")).contains("file_busy"));
    }

    public void testBusyChangedFileNeverRecommendsSave() throws Exception {
        DomainFile file = baseFile();
        when(file.isCheckedOut()).thenReturn(true);
        when(file.isBusy()).thenReturn(true);
        when(file.isChanged()).thenReturn(true);
        when(file.canSave()).thenReturn(true);

        Map<String, Object> status = ProjectFileLifecycle.inspect(file);

        assertEquals("resolve_edit_blockers", status.get("next_action"));
        Map<?, ?> blockers = (Map<?, ?>) status.get("blockers");
        assertTrue(((List<?>) blockers.get("save")).contains("file_busy"));
    }

    public void testStaleCheckoutBlocksCheckinWhenMergeIsUnavailable() throws Exception {
        DomainFile file = baseFile();
        when(file.isCheckedOut()).thenReturn(true);
        when(file.isLatestVersion()).thenReturn(false);
        when(file.canCheckin()).thenReturn(true);
        when(file.canMerge()).thenReturn(false);

        Map<String, Object> status = ProjectFileLifecycle.inspect(file);

        assertEquals("resolve_merge_blockers", status.get("next_action"));
        Map<?, ?> blockers = (Map<?, ?>) status.get("blockers");
        assertTrue(((List<?>) blockers.get("checkin")).contains("not_latest_version"));
        assertTrue(((List<?>) blockers.get("checkin")).contains("merge_unavailable"));
        assertTrue(((List<?>) blockers.get("merge")).contains("domain_file_refused_merge"));
    }

    public void testReadOnlyAndNonWritableFilesResolveEditBlockersFirst() throws Exception {
        DomainFile readOnly = baseFile();
        when(readOnly.isCheckedOut()).thenReturn(true);
        when(readOnly.isReadOnly()).thenReturn(true);
        when(readOnly.isChanged()).thenReturn(true);
        when(readOnly.canSave()).thenReturn(true);
        when(readOnly.canCheckin()).thenReturn(true);

        Map<String, Object> readOnlyStatus = ProjectFileLifecycle.inspect(readOnly);
        assertEquals("resolve_edit_blockers", readOnlyStatus.get("next_action"));
        Map<?, ?> readOnlyBlockers = (Map<?, ?>) readOnlyStatus.get("blockers");
        assertTrue(((List<?>) readOnlyBlockers.get("edit")).contains("read_only"));

        DomainFile nonWritable = baseFile();
        when(nonWritable.isCheckedOut()).thenReturn(true);
        when(nonWritable.isInWritableProject()).thenReturn(false);
        when(nonWritable.canCheckin()).thenReturn(true);

        Map<String, Object> nonWritableStatus = ProjectFileLifecycle.inspect(nonWritable);
        assertEquals("resolve_edit_blockers", nonWritableStatus.get("next_action"));
        Map<?, ?> nonWritableBlockers = (Map<?, ?>) nonWritableStatus.get("blockers");
        assertTrue(((List<?>) nonWritableBlockers.get("edit")).contains("project_not_writable"));
    }

    public void testHealthyChangedFileRecommendsSaveOnlyWhenSaveHasNoBlockers() throws Exception {
        DomainFile file = baseFile();
        when(file.isCheckedOut()).thenReturn(true);
        when(file.isChanged()).thenReturn(true);
        when(file.canSave()).thenReturn(true);

        Map<String, Object> status = ProjectFileLifecycle.inspect(file);

        assertEquals("save", status.get("next_action"));
        Map<?, ?> blockers = (Map<?, ?>) status.get("blockers");
        assertEquals(List.of(), blockers.get("save"));
    }

    public void testUnversionedFileDoesNotPretendCheckoutIsAvailable() throws Exception {
        DomainFile file = baseFile();
        when(file.isVersioned()).thenReturn(false);
        when(file.isLatestVersion()).thenReturn(true);
        when(file.canAddToRepository()).thenReturn(true);

        Map<String, Object> status = ProjectFileLifecycle.inspect(file);

        assertEquals("add_to_version_control", status.get("next_action"));
        Map<?, ?> blockers = (Map<?, ?>) status.get("blockers");
        assertTrue(((List<?>) blockers.get("checkout")).contains("not_versioned"));
        assertEquals(true, status.get("can_add_to_repository"));
    }

    public void testStatusReportsCheckoutOwnedByAnotherComputer() throws Exception {
        DomainFile file = baseFile();
        ItemCheckoutStatus checkout = mock(ItemCheckoutStatus.class);
        when(file.isCheckedOut()).thenReturn(false);
        when(file.getCheckouts()).thenReturn(new ItemCheckoutStatus[] { checkout });
        when(checkout.getCheckoutId()).thenReturn(77L);
        when(checkout.getUser()).thenReturn("other-analyst");
        when(checkout.getCheckoutVersion()).thenReturn(8);
        when(checkout.getUserHostName()).thenReturn("WORKSTATION-2");

        Map<String, Object> status = ProjectFileLifecycle.inspect(file);

        assertEquals(1, status.get("active_checkout_count"));
        assertEquals(true, status.get("checked_out_elsewhere"));
        List<?> active = (List<?>) status.get("active_checkouts");
        Map<?, ?> row = (Map<?, ?>) active.get(0);
        assertEquals(77L, row.get("checkout_id"));
        assertEquals("other-analyst", row.get("user"));
        assertEquals("WORKSTATION-2", row.get("user_host"));
    }

    public void testHeadlessProviderReadsLifecycleFromOpenProjectDomainFile() throws Exception {
        Project project = mock(Project.class);
        ProjectData data = mock(ProjectData.class);
        DomainFile file = baseFile();
        when(project.getProjectData()).thenReturn(data);
        when(data.getFile("/BlackOps.exe")).thenReturn(file);

        HeadlessProgramProvider provider = new HeadlessProgramProvider(project);
        Map<String, Object> status =
            provider.getProjectFileLifecycleStatus("/BlackOps.exe");

        assertEquals(true, status.get("success"));
        assertEquals("project_domain_file", status.get("lifecycle_scope"));
        assertEquals("/BlackOps.exe", status.get("path"));
        assertEquals(true, status.get("is_latest_version"));
    }

    private static DomainFile baseFile() throws Exception {
        DomainFile file = mock(DomainFile.class);
        when(file.getName()).thenReturn("BlackOps.exe");
        when(file.getPathname()).thenReturn("/BlackOps.exe");
        when(file.getContentType()).thenReturn("Program");
        when(file.getVersion()).thenReturn(7);
        when(file.getLatestVersion()).thenReturn(8);
        when(file.isVersioned()).thenReturn(true);
        when(file.isLatestVersion()).thenReturn(true);
        when(file.isInWritableProject()).thenReturn(true);
        return file;
    }
}
