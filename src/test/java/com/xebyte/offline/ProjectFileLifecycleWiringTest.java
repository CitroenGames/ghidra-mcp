package com.xebyte.offline;

import junit.framework.TestCase;

import java.nio.file.Files;
import java.nio.file.Paths;

/** Locks in GUI/headless lifecycle preflight wiring without a live Ghidra. */
public class ProjectFileLifecycleWiringTest extends TestCase {

    public void testGuiPublishesProjectFileStatusThroughLiveSchemaScanner() throws Exception {
        String plugin = Files.readString(Paths.get(
            "src/main/java/com/xebyte/GhidraMCPPlugin.java"));
        assertTrue(plugin.contains("new AnnotationScanner(programProvider, this,"));
        assertTrue(plugin.contains("@McpTool(path = \"/project_file_status\""));
        assertFalse(plugin.contains(
            "server.createContext(\"/project_file_status\""));
        assertTrue(plugin.contains("ProjectFileLifecycle.inspect(file)"));
        assertTrue(plugin.contains("@McpTool(path = \"/checkout_program\""));
        assertTrue(plugin.contains("@McpTool(path = \"/checkin_program\""));
        assertTrue(plugin.contains("ProjectFileVersionControl.checkout("));
        assertTrue(plugin.contains("ProjectFileVersionControl.checkin("));
        assertTrue(plugin.contains("this::saveProjectFileOnEdt"));
    }

    public void testHeadlessPublishesTheSameGuardedLifecycleTools() throws Exception {
        String service = Files.readString(Paths.get(
            "src/main/java/com/xebyte/headless/HeadlessManagementService.java"));
        String provider = Files.readString(Paths.get(
            "src/main/java/com/xebyte/headless/HeadlessProgramProvider.java"));

        assertTrue(service.contains("@McpTool(path = \"/checkout_program\""));
        assertTrue(service.contains("@McpTool(path = \"/checkin_program\""));
        assertTrue(provider.contains("ProjectFileVersionControl.checkout("));
        assertTrue(provider.contains("ProjectFileVersionControl.checkin("));
    }

    public void testHeadlessRepositoryInfoDoesNotFakeProjectLifecycleState() throws Exception {
        String manager = Files.readString(Paths.get(
            "src/main/java/com/xebyte/headless/GhidraServerManager.java"));
        assertTrue(manager.contains("\\\"lifecycle_scope\\\": \\\"repository_only\\\""));
        assertTrue(manager.contains("\\\"project_file_state_supported\\\": false"));
        assertTrue(manager.contains("/project_file_status"));
    }
}
