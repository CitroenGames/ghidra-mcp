package com.xebyte.offline;

import com.xebyte.core.ProjectFileVersionControl;
import ghidra.framework.data.CheckinHandler;
import ghidra.framework.model.DomainFile;
import ghidra.framework.store.ItemCheckoutStatus;
import ghidra.util.task.TaskMonitor;
import junit.framework.TestCase;

import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Offline mutation-contract tests for guarded project version control. */
public class ProjectFileVersionControlTest extends TestCase {

    public void testCheckoutDryRunDoesNotAcquireCheckout() throws Exception {
        DomainFile file = baseFile();
        when(file.canCheckout()).thenReturn(true);

        Map<String, Object> result = ProjectFileVersionControl.checkout(
            file, true, 8, true, TaskMonitor.DUMMY);

        assertEquals(true, result.get("success"));
        assertEquals("ready_to_checkout", result.get("status"));
        assertEquals(true, result.get("dry_run"));
        verify(file, never()).checkout(anyBoolean(), any(TaskMonitor.class));
    }

    public void testCheckoutVerifiesLatestCheckedOutPostState() throws Exception {
        DomainFile file = baseFile();
        AtomicBoolean checkedOut = new AtomicBoolean(false);
        when(file.isCheckedOut()).thenAnswer(invocation -> checkedOut.get());
        when(file.canCheckout()).thenReturn(true);
        when(file.checkout(anyBoolean(), any(TaskMonitor.class))).thenAnswer(invocation -> {
            checkedOut.set(true);
            return true;
        });

        Map<String, Object> result = ProjectFileVersionControl.checkout(
            file, true, 8, false, TaskMonitor.DUMMY);

        assertEquals(true, result.get("success"));
        assertEquals("checked_out", result.get("status"));
        assertEquals(true, result.get("verified"));
    }

    public void testCheckoutDoesNotTreatStaleExistingCheckoutAsIdempotent() throws Exception {
        DomainFile file = baseFile();
        when(file.isCheckedOut()).thenReturn(true);
        when(file.isLatestVersion()).thenReturn(false);

        Map<String, Object> result = ProjectFileVersionControl.checkout(
            file, true, -1, true, TaskMonitor.DUMMY);

        assertEquals(false, result.get("success"));
        assertEquals("merge_required", result.get("error_code"));
        assertFalse(result.containsKey("idempotent"));
    }

    public void testCheckinRefusesStaleCheckoutBeforeSave() throws Exception {
        DomainFile file = baseFile();
        when(file.isCheckedOut()).thenReturn(true);
        when(file.isLatestVersion()).thenReturn(false);
        when(file.isChanged()).thenReturn(true);
        when(file.canCheckin()).thenReturn(true);

        ProjectFileVersionControl.SaveOperation saver = mock(
            ProjectFileVersionControl.SaveOperation.class);
        Map<String, Object> result = ProjectFileVersionControl.checkin(
            file, "reviewed batch", true, false, 7, 8, -1,
            false, TaskMonitor.DUMMY, saver);

        assertEquals(false, result.get("success"));
        assertEquals("merge_required", result.get("error_code"));
        verify(saver, never()).save(any(), any(), any());
        verify(file, never()).checkin(any(CheckinHandler.class), any(TaskMonitor.class));
    }

    public void testCheckinSavesBumpsVersionAndKeepsCheckout() throws Exception {
        DomainFile file = mock(DomainFile.class);
        AtomicInteger version = new AtomicInteger(8);
        AtomicBoolean changed = new AtomicBoolean(true);
        AtomicBoolean modified = new AtomicBoolean(true);
        AtomicBoolean checkedOut = new AtomicBoolean(true);
        ItemCheckoutStatus checkout = mock(ItemCheckoutStatus.class);

        when(file.getName()).thenReturn("BlackOps.exe");
        when(file.getPathname()).thenReturn("/BlackOps.exe");
        when(file.getContentType()).thenReturn("Program");
        when(file.getVersion()).thenAnswer(invocation -> version.get());
        when(file.getLatestVersion()).thenAnswer(invocation -> version.get());
        when(file.isVersioned()).thenReturn(true);
        when(file.isLatestVersion()).thenReturn(true);
        when(file.isCheckedOut()).thenAnswer(invocation -> checkedOut.get());
        when(file.isChanged()).thenAnswer(invocation -> changed.get());
        when(file.modifiedSinceCheckout()).thenAnswer(invocation -> modified.get());
        when(file.isInWritableProject()).thenReturn(true);
        when(file.canCheckin()).thenAnswer(invocation -> !changed.get());
        when(file.getCheckoutStatus()).thenReturn(checkout);
        when(checkout.getUser()).thenReturn("analyst");
        when(checkout.getCheckoutId()).thenReturn(42L);
        when(checkout.getCheckoutVersion()).thenAnswer(invocation -> version.get());

        ProjectFileVersionControl.SaveOperation saver = (target, comment, monitor) -> {
            assertEquals("c5s166: review 20 functions", comment);
            changed.set(false);
            modified.set(true);
        };
        doAnswer(invocation -> {
            CheckinHandler handler = invocation.getArgument(0);
            assertTrue(handler.keepCheckedOut());
            assertEquals("c5s166: review 20 functions", handler.getComment());
            version.incrementAndGet();
            modified.set(false);
            return null;
        }).when(file).checkin(any(CheckinHandler.class), any(TaskMonitor.class));

        Map<String, Object> result = ProjectFileVersionControl.checkin(
            file, "c5s166: review 20 functions", true, false,
            8, 8, 42L, false, TaskMonitor.DUMMY, saver);

        assertEquals(true, result.get("success"));
        assertEquals("checked_in", result.get("status"));
        assertEquals(true, result.get("saved"));
        assertEquals(8, result.get("version_before"));
        assertEquals(9, result.get("version"));
        assertEquals(true, result.get("version_bumped"));
        assertEquals(true, result.get("verified"));
    }

    public void testCheckinRefusesUnexpectedCheckoutId() throws Exception {
        DomainFile file = baseFile();
        ItemCheckoutStatus checkout = mock(ItemCheckoutStatus.class);
        when(file.isCheckedOut()).thenReturn(true);
        when(file.isChanged()).thenReturn(true);
        when(file.canCheckin()).thenReturn(true);
        when(file.getCheckoutStatus()).thenReturn(checkout);
        when(checkout.getCheckoutId()).thenReturn(99L);

        Map<String, Object> result = ProjectFileVersionControl.checkin(
            file, "reviewed batch", true, false, 7, 8, 42L,
            true, TaskMonitor.DUMMY, (target, comment, monitor) -> {});

        assertEquals(false, result.get("success"));
        assertEquals("stale_precondition", result.get("error_code"));
    }

    public void testCheckinRefusesEmptyVersionByDefault() throws Exception {
        DomainFile file = baseFile();
        when(file.isCheckedOut()).thenReturn(true);
        when(file.canCheckin()).thenReturn(true);

        Map<String, Object> result = ProjectFileVersionControl.checkin(
            file, "repeat", true, false, 7, 8, -1L,
            true, TaskMonitor.DUMMY, (target, comment, monitor) -> {});

        assertEquals(false, result.get("success"));
        assertEquals("no_changes", result.get("error_code"));
    }

    public void testOpenFileCannotDropCheckout() throws Exception {
        DomainFile file = baseFile();
        when(file.isCheckedOut()).thenReturn(true);
        when(file.isOpen()).thenReturn(true);
        when(file.isChanged()).thenReturn(true);
        when(file.canCheckin()).thenReturn(true);

        Map<String, Object> result = ProjectFileVersionControl.checkin(
            file, "reviewed batch", false, false, 7, 8, -1L,
            true, TaskMonitor.DUMMY, (target, comment, monitor) -> {});

        assertEquals(false, result.get("success"));
        assertEquals("open_file_requires_keep_checkout", result.get("error_code"));
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
