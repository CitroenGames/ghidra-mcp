package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InOrder;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class FunctionServiceResetPrototypeTest {

    private RecordingThreadingStrategy threading;
    private Program program;
    private FunctionManager functionManager;
    private Address address;
    private FunctionDouble function;
    private TestFunctionService service;

    @Before
    public void setUp() throws Exception {
        threading = new RecordingThreadingStrategy();
        program = mock(Program.class);
        functionManager = mock(FunctionManager.class);
        AddressFactory addressFactory = mock(AddressFactory.class);
        address = mock(Address.class);
        when(address.toString()).thenReturn("00401000");
        when(addressFactory.getAddress("0x401000")).thenReturn(address);
        when(program.getAddressFactory()).thenReturn(addressFactory);
        when(program.getFunctionManager()).thenReturn(functionManager);

        function = new FunctionDouble("DocumentedFunction", SourceType.USER_DEFINED, false);
        when(functionManager.getFunctionAt(address)).thenReturn(function.function);

        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getCurrentProgram()).thenReturn(program);
        when(provider.getProgram(anyString())).thenReturn(program);
        service = new TestFunctionService(provider, threading);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void resetsInRequiredOrderAndReturnsVerifiedSnapshots() throws Exception {
        Response response = service.resetFunctionPrototype(
            "0x401000", " user_defined ", false, "");

        assertTrue(response.toJson(), response instanceof Response.Ok);
        assertEquals(1, threading.commits);
        assertEquals(0, threading.rollbacks);

        Map<String, Object> body = (Map<String, Object>) ((Response.Ok) response).data();
        assertEquals("success", body.get("status"));
        assertEquals(Boolean.TRUE, body.get("verified"));
        Map<String, Object> before = (Map<String, Object>) body.get("before");
        Map<String, Object> after = (Map<String, Object>) body.get("after");
        assertEquals(before.get("preserved_metadata"), after.get("preserved_metadata"));
        Map<String, Object> signature = (Map<String, Object>) after.get("signature");
        assertEquals("DEFAULT", signature.get("source"));
        assertEquals(0, ((Number) signature.get("explicit_parameter_count")).intValue());
        assertEquals(Boolean.TRUE, signature.get("return_is_default"));
        assertEquals(Boolean.FALSE, signature.get("custom_variable_storage"));
        assertEquals(Boolean.FALSE, signature.get("varargs"));
        assertEquals(Boolean.TRUE, signature.get("stack_purge_unknown"));

        InOrder order = inOrder(function.function);
        order.verify(function.function).updateFunction(
            eq(Function.UNKNOWN_CALLING_CONVENTION_STRING),
            same(service.defaultReturn),
            eq(List.of()),
            eq(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS),
            eq(false),
            eq(SourceType.DEFAULT));
        order.verify(function.function).setReturnType(isNull(), eq(SourceType.DEFAULT));
        order.verify(function.function).setVarArgs(false);
        order.verify(function.function).setCustomVariableStorage(false);
        order.verify(function.function).setSignatureSource(SourceType.DEFAULT);
        order.verify(function.function).setStackPurgeSize(Function.UNKNOWN_STACK_DEPTH_CHANGE);

        verify(function.function, never()).setName(anyString(), any(SourceType.class));
        verify(function.function, never()).setComment(anyString());
        verify(function.function, never()).setRepeatableComment(anyString());
        verify(function.function, never()).setInline(anyBoolean());
        verify(function.function, never()).setNoReturn(anyBoolean());
        verify(function.function, never()).setBody(any(AddressSetView.class));
        verify(function.function, never()).setThunkedFunction(any(Function.class));
    }

    @Test
    public void guardMismatchRefusesBeforeAnyFunctionWriteAndRollsBack() throws Exception {
        function.source = SourceType.ANALYSIS;

        Response response = service.resetFunctionPrototype(
            "0x401000", "USER_DEFINED", false, "");

        assertTrue(response instanceof Response.Err);
        assertTrue(response.toJson(), response.toJson().contains("guard mismatch"));
        assertTrue(response.toJson(), response.toJson().contains("ANALYSIS"));
        assertEquals(0, threading.commits);
        assertEquals(1, threading.rollbacks);
        verify(function.function, never()).updateFunction(
            anyString(), any(Variable.class), anyList(),
            any(Function.FunctionUpdateType.class), anyBoolean(), any(SourceType.class));
    }

    @Test
    public void explicitAnalysisGuardAllowsAnalysisSignatureReset() throws Exception {
        function.source = SourceType.ANALYSIS;

        Response response = service.resetFunctionPrototype(
            "0x401000", "analysis", false, "");

        assertTrue(response.toJson(), response instanceof Response.Ok);
        assertEquals(SourceType.DEFAULT, function.source);
        assertEquals(1, threading.commits);
    }

    @Test
    public void verificationFailureEscapesWriteActionAndRequestsRollback() throws Exception {
        function.ignoreSignatureSourceWrite = true;

        Response response = service.resetFunctionPrototype(
            "0x401000", "USER_DEFINED", false, "");

        assertTrue(response instanceof Response.Err);
        assertTrue(response.toJson(), response.toJson().contains("verification failed"));
        assertEquals(0, threading.commits);
        assertEquals(1, threading.rollbacks);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void defaultWithExplicitDefaultIsIdempotentNoFunctionWrite() throws Exception {
        function.source = SourceType.DEFAULT;

        Response response = service.resetFunctionPrototype(
            "0x401000", "DEFAULT", false, "");

        assertTrue(response.toJson(), response instanceof Response.Ok);
        Map<String, Object> body = (Map<String, Object>) ((Response.Ok) response).data();
        assertEquals("noop", body.get("status"));
        assertEquals(Boolean.TRUE, body.get("idempotent"));
        assertEquals(body.get("before"), body.get("after"));
        assertEquals(1, threading.commits);
        verify(function.function, never()).updateFunction(
            anyString(), any(Variable.class), anyList(),
            any(Function.FunctionUpdateType.class), anyBoolean(), any(SourceType.class));
    }

    @Test
    public void thunkRequiresExplicitOverride() throws Exception {
        function.thunk = true;

        Response refused = service.resetFunctionPrototype(
            "0x401000", "USER_DEFINED", false, "");
        assertTrue(refused instanceof Response.Err);
        assertTrue(refused.toJson(), refused.toJson().contains("allow_thunk=true"));
        verify(function.function, never()).updateFunction(
            anyString(), any(Variable.class), anyList(),
            any(Function.FunctionUpdateType.class), anyBoolean(), any(SourceType.class));

        Response allowed = service.resetFunctionPrototype(
            "0x401000", "USER_DEFINED", true, "");
        assertTrue(allowed.toJson(), allowed instanceof Response.Ok);
        assertSame(function.thunkTarget, function.function.getThunkedFunction(false));
        verify(function.function).updateFunction(
            anyString(), any(Variable.class), anyList(),
            any(Function.FunctionUpdateType.class), anyBoolean(), any(SourceType.class));
    }

    @Test
    public void invalidInputDoesNotOpenTransaction() throws Exception {
        Response missingAddress = service.resetFunctionPrototype(
            " ", "USER_DEFINED", false, "");
        assertTrue(missingAddress instanceof Response.Err);

        Response invalidSource = service.resetFunctionPrototype(
            "0x401000", "AI", false, "");
        assertTrue(invalidSource instanceof Response.Err);
        assertTrue(invalidSource.toJson(), invalidSource.toJson().contains("not resettable"));

        Response nonsense = service.resetFunctionPrototype(
            "0x401000", "guessed", false, "");
        assertTrue(nonsense instanceof Response.Err);
        assertTrue(nonsense.toJson(), nonsense.toJson().contains("must be one of"));
        assertEquals(0, threading.commits);
        assertEquals(0, threading.rollbacks);
        assertEquals(0, threading.writeCalls);
    }

    private static final class RecordingThreadingStrategy implements ThreadingStrategy {
        int writeCalls;
        int commits;
        int rollbacks;

        @Override
        public <T> T executeRead(Callable<T> action) throws Exception {
            return action.call();
        }

        @Override
        public <T> T executeWrite(Program ignored, String transactionName, Callable<T> action)
                throws Exception {
            writeCalls++;
            try {
                T result = action.call();
                commits++;
                return result;
            }
            catch (Exception e) {
                rollbacks++;
                throw e;
            }
        }

        @Override
        public boolean isHeadless() {
            return true;
        }
    }

    private static final class TestFunctionService extends FunctionService {
        final Variable defaultReturn = mock(Variable.class);
        boolean resetApplied;

        TestFunctionService(ProgramProvider provider, ThreadingStrategy threadingStrategy) {
            super(provider, threadingStrategy);
        }

        @Override
        Variable createDefaultReturnParameter(Program ignored) {
            return defaultReturn;
        }

        @Override
        void resetFunctionPrototypeState(Function function, Program ignored) throws Exception {
            resetFunctionPrototypeState(function, defaultReturn, null);
            resetApplied = true;
        }

        @Override
        boolean isDefaultReturnType(DataType ignored) {
            return resetApplied;
        }
    }

    private static final class FunctionDouble {
        final Function function = mock(Function.class);
        final Function thunkTarget = mock(Function.class);
        SourceType source;
        String callingConvention = "__cdecl";
        Parameter[] parameters;
        boolean customStorage = true;
        boolean varArgs = true;
        int stackPurge = 16;
        boolean thunk;
        boolean ignoreSignatureSourceWrite;

        FunctionDouble(String name, SourceType source, boolean thunk) throws Exception {
            this.source = source;
            this.thunk = thunk;
            Parameter parameter = mock(Parameter.class);
            when(parameter.isAutoParameter()).thenReturn(false);
            parameters = new Parameter[]{parameter};

            Address entry = mock(Address.class);
            when(entry.toString()).thenReturn("00401000");
            Address bodyMin = mock(Address.class);
            Address bodyMax = mock(Address.class);
            when(bodyMin.toString()).thenReturn("00401000");
            when(bodyMax.toString()).thenReturn("0040103f");
            AddressSetView body = mock(AddressSetView.class);
            when(body.isEmpty()).thenReturn(false);
            when(body.getMinAddress()).thenReturn(bodyMin);
            when(body.getMaxAddress()).thenReturn(bodyMax);
            when(body.getNumAddressRanges()).thenReturn(1);
            when(body.getNumAddresses()).thenReturn(64L);
            Namespace namespace = mock(Namespace.class);
            when(namespace.getName(true)).thenReturn("Global::Subsystem");
            FunctionTag tag = mock(FunctionTag.class);
            when(tag.getName()).thenReturn("custom-abi");
            Address targetEntry = mock(Address.class);
            when(targetEntry.toString()).thenReturn("00402000");
            when(thunkTarget.getEntryPoint()).thenReturn(targetEntry);

            when(function.getName()).thenReturn(name);
            when(function.getEntryPoint()).thenReturn(entry);
            when(function.getParentNamespace()).thenReturn(namespace);
            when(function.getComment()).thenReturn("plate");
            when(function.getRepeatableComment()).thenReturn("repeatable");
            when(function.getTags()).thenReturn(Set.of(tag));
            when(function.isInline()).thenReturn(true);
            when(function.hasNoReturn()).thenReturn(true);
            when(function.getBody()).thenReturn(body);
            when(function.isExternal()).thenReturn(false);
            when(function.getSignatureSource()).thenAnswer(invocation -> this.source);
            when(function.getCallingConventionName())
                .thenAnswer(invocation -> this.callingConvention);
            when(function.getParameterCount())
                .thenAnswer(invocation -> this.parameters.length);
            when(function.getParameters()).thenAnswer(invocation -> this.parameters);
            when(function.getReturnType()).thenReturn(null);
            when(function.hasCustomVariableStorage())
                .thenAnswer(invocation -> this.customStorage);
            when(function.hasVarArgs()).thenAnswer(invocation -> this.varArgs);
            when(function.getStackPurgeSize()).thenAnswer(invocation -> this.stackPurge);
            when(function.isThunk()).thenAnswer(invocation -> this.thunk);
            when(function.getThunkedFunction(false))
                .thenAnswer(invocation -> this.thunk ? thunkTarget : null);

            doAnswer(invocation -> {
                callingConvention = invocation.getArgument(0);
                parameters = new Parameter[0];
                customStorage = false;
                if (!ignoreSignatureSourceWrite) {
                    this.source = invocation.getArgument(5);
                }
                return null;
            }).when(function).updateFunction(anyString(), any(Variable.class), anyList(),
                any(Function.FunctionUpdateType.class), anyBoolean(), any(SourceType.class));
            doAnswer(invocation -> {
                return null;
            }).when(function).setReturnType(any(DataType.class), any(SourceType.class));
            doAnswer(invocation -> {
                varArgs = invocation.getArgument(0);
                return null;
            }).when(function).setVarArgs(anyBoolean());
            doAnswer(invocation -> {
                customStorage = invocation.getArgument(0);
                return null;
            }).when(function).setCustomVariableStorage(anyBoolean());
            doAnswer(invocation -> {
                if (!ignoreSignatureSourceWrite) {
                    this.source = invocation.getArgument(0);
                }
                return null;
            }).when(function).setSignatureSource(any(SourceType.class));
            doAnswer(invocation -> {
                stackPurge = invocation.getArgument(0);
                return null;
            }).when(function).setStackPurgeSize(anyInt());
        }
    }
}
