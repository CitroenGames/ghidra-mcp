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
    }

    public void testHeadlessRepositoryInfoDoesNotFakeProjectLifecycleState() throws Exception {
        String manager = Files.readString(Paths.get(
            "src/main/java/com/xebyte/headless/GhidraServerManager.java"));
        assertTrue(manager.contains("\\\"lifecycle_scope\\\": \\\"repository_only\\\""));
        assertTrue(manager.contains("\\\"project_file_state_supported\\\": false"));
        assertTrue(manager.contains("/project_file_status"));
    }
}
