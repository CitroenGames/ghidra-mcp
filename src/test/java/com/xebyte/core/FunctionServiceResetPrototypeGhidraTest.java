package com.xebyte.core;

import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/** Real in-memory Ghidra transaction coverage; never opens a project database. */
public class FunctionServiceResetPrototypeGhidraTest {

    private ProgramBuilder builder;
    private ProgramDB program;
    private Function function;
    private HeadlessProgramProvider provider;

    @BeforeClass
    public static void initializeGhidra() throws Exception {
        String installDir = System.getenv("GHIDRA_INSTALL_DIR");
        assumeTrue("GHIDRA_INSTALL_DIR is required for real Ghidra tests",
            installDir != null && !installDir.isBlank());
        try {
            Class.forName("org.apache.logging.log4j.LogManager");
        }
        catch (ClassNotFoundException e) {
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
        builder = new ProgramBuilder("reset-function-prototype", ProgramBuilder._X64, "gcc", this);
        program = builder.getProgram();
        builder.createMemory(".text", "0x1000", 0x100);
        builder.setBytes("0x1000", "c3");
        builder.disassemble("0x1000", 1);
        function = builder.createFunction("0x1000");
        int transaction = program.startTransaction("create forced prototype fixture");
        boolean commit = false;
        try {
            function.setName("reset_target", SourceType.USER_DEFINED);
            function.updateFunction("__cdecl",
                new ReturnParameterImpl(DWordDataType.dataType, program),
                List.of(new ParameterImpl("value", DWordDataType.dataType, program)),
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                false, SourceType.USER_DEFINED);
            function.setVarArgs(true);
            function.setStackPurgeSize(16);
            function.setSignatureSource(SourceType.USER_DEFINED);
            function.setComment("plate stays");
            function.setRepeatableComment("repeatable stays");
            function.addTag("prototype-reset-test");
            function.setInline(true);
            function.setNoReturn(true);
            commit = true;
        }
        finally {
            program.endTransaction(transaction, commit);
        }
        provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
    }

    @After
    public void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    public void resetsRealFunctionAndPreservesMetadata() {
        FunctionService service =
            new FunctionService(provider, new DirectThreadingStrategy());
        Map<String, Object> before = service.snapshotFunctionPrototypeState(function);

        Response response = service.resetFunctionPrototype(
            "0x1000", "USER_DEFINED", false, "");

        assertTrue(response.toJson(), response instanceof Response.Ok);
        assertEquals(SourceType.DEFAULT, function.getSignatureSource());
        assertEquals(0, function.getParameters().length);
        assertTrue(DataType.DEFAULT.isEquivalent(function.getReturnType()));
        assertFalse(function.hasCustomVariableStorage());
        assertFalse(function.hasVarArgs());
        assertEquals(Function.UNKNOWN_STACK_DEPTH_CHANGE, function.getStackPurgeSize());
        assertTrue(Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(
                function.getCallingConventionName())
            || Function.DEFAULT_CALLING_CONVENTION_STRING.equals(
                function.getCallingConventionName()));
        Map<String, Object> after = service.snapshotFunctionPrototypeState(function);
        assertEquals(before.get("preserved_metadata"), after.get("preserved_metadata"));

        Map<String, Object> body = (Map<String, Object>) ((Response.Ok) response).data();
        assertEquals(Boolean.TRUE, body.get("verified"));
    }

    @Test
    public void verificationFailureRollsBackRealProgramTransaction() {
        FunctionService service = new FunctionService(provider, new DirectThreadingStrategy()) {
            @Override
            boolean isDefaultReturnType(DataType ignored) {
                return false;
            }
        };

        Response response = service.resetFunctionPrototype(
            "0x1000", "USER_DEFINED", false, "");

        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(response.toJson(), response.toJson().contains("verification failed"));
        assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
        assertEquals(1, function.getParameters().length);
        assertFalse(DataType.DEFAULT.isEquivalent(function.getReturnType()));
        assertTrue(function.hasVarArgs());
        assertEquals(16, function.getStackPurgeSize());
        assertEquals("plate stays", function.getComment());
        assertEquals("repeatable stays", function.getRepeatableComment());
        assertTrue(function.isInline());
        assertTrue(function.hasNoReturn());
    }
}
