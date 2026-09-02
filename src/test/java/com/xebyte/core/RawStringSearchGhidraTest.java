package com.xebyte.core;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/** Real in-memory Ghidra coverage; never opens or writes a project database. */
public class RawStringSearchGhidraTest {

    private ProgramBuilder builder;
    private ProgramDB program;

    @BeforeClass
    public static void initializeGhidra() throws Exception {
        String installDir = System.getenv("GHIDRA_INSTALL_DIR");
        assumeTrue("GHIDRA_INSTALL_DIR is required for real Ghidra tests",
                installDir != null && !installDir.isBlank());
        try {
            Class.forName("org.apache.logging.log4j.LogManager");
        } catch (ClassNotFoundException e) {
            assumeTrue("Ghidra's Log4j runtime is required for ProgramBuilder tests", false);
        }
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(new GhidraApplicationLayout(new File(installDir)),
                    configuration);
        }
    }

    @Before
    public void setUp() throws Exception {
        builder = new ProgramBuilder("raw-string-search", ProgramBuilder._X64, "gcc", this);
        program = builder.getProgram();
        builder.createMemory(".rdata", "0x1000", 0x200);
        // Ghidra's one defined string intentionally includes a two-byte prefix. The raw
        // endpoint must still find the literal at +2, where /search_strings cannot treat
        // it as a separate defined-string boundary.
        builder.createString("0x1000", "4>getattachtagname");
    }

    @After
    public void tearDown() {
        if (builder != null) builder.dispose();
    }

    @Test
    @SuppressWarnings("unchecked")
    public void findsLiteralInsideDefinedStringWithoutChangingProgram() {
        ProgramProvider provider = new ProgramProvider() {
            @Override public Program getCurrentProgram() { return program; }
            @Override public Program getProgram(String name) { return program; }
            @Override public Program[] getAllOpenPrograms() { return new Program[]{program}; }
            @Override public void setCurrentProgram(Program ignored) {}
        };
        ListingService service = new ListingService(provider);
        long before = program.getModificationNumber();

        Response response = service.searchRawStrings(
                "getattachtagname", "ascii", 0, 10, "raw-string-search");

        assertTrue(response.toJson(), response instanceof Response.Ok);
        Map<String, Object> result = (Map<String, Object>) ((Response.Ok) response).data();
        List<Map<String, Object>> matches =
                (List<Map<String, Object>>) result.get("matches");
        assertEquals(1, matches.size());
        assertTrue(matches.get(0).get("address").toString().endsWith("1002"));
        Map<String, Object> containing =
                (Map<String, Object>) matches.get(0).get("containing_defined_data");
        assertEquals(2L, containing.get("byte_offset"));
        assertEquals(Boolean.FALSE, containing.get("match_at_start"));
        assertEquals(before, program.getModificationNumber());
    }
}
