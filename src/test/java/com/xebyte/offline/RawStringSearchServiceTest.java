package com.xebyte.offline;

import com.xebyte.core.ListingService;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;
import junit.framework.TestCase;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** Offline, read-only coverage for the raw-byte string-search endpoint. */
public class RawStringSearchServiceTest extends TestCase {

    private static final GenericAddressSpace SPACE =
            new GenericAddressSpace("ram", 32, 1, AddressSpace.TYPE_RAM);

    private record BlockBytes(MemoryBlock block, long start, byte[] bytes) {}

    private static final class Fixture {
        final Program program = mock(Program.class);
        final ProgramProvider provider = mock(ProgramProvider.class);
        final Memory memory = mock(Memory.class);
        final Listing listing = mock(Listing.class);
        final List<BlockBytes> blocks = new ArrayList<>();

        Fixture() throws Exception {
            when(provider.getCurrentProgram()).thenReturn(program);
            when(program.getMemory()).thenReturn(memory);
            when(program.getListing()).thenReturn(listing);
            when(program.getName()).thenReturn("raw-search-test");

            when(memory.findBytes(any(Address.class), any(Address.class), any(byte[].class),
                    isNull(), eq(true), any(TaskMonitor.class))).thenAnswer(invocation -> {
                Address from = invocation.getArgument(0);
                Address to = invocation.getArgument(1);
                byte[] pattern = invocation.getArgument(2);
                for (BlockBytes candidate : blocks) {
                    long first = Math.max(from.getOffset(), candidate.start());
                    long last = Math.min(to.getOffset(),
                            candidate.start() + candidate.bytes().length - pattern.length);
                    for (long address = first; address <= last; address++) {
                        int index = (int) (address - candidate.start());
                        boolean matches = true;
                        for (int i = 0; i < pattern.length; i++) {
                            if (candidate.bytes()[index + i] != pattern[i]) {
                                matches = false;
                                break;
                            }
                        }
                        if (matches) return SPACE.getAddress(address);
                    }
                }
                return null;
            });
            when(memory.getByte(any(Address.class))).thenAnswer(invocation -> {
                long address = ((Address) invocation.getArgument(0)).getOffset();
                for (BlockBytes candidate : blocks) {
                    int index = (int) (address - candidate.start());
                    if (index >= 0 && index < candidate.bytes().length) {
                        return candidate.bytes()[index];
                    }
                }
                throw new AssertionError("unexpected byte read at " + Long.toHexString(address));
            });
        }

        MemoryBlock addBlock(String name, long start, byte[] bytes,
                             boolean initialized, boolean loaded) {
            MemoryBlock block = mock(MemoryBlock.class);
            Address blockStart = SPACE.getAddress(start);
            Address blockEnd = SPACE.getAddress(start + bytes.length - 1L);
            when(block.getName()).thenReturn(name);
            when(block.getStart()).thenReturn(blockStart);
            when(block.getEnd()).thenReturn(blockEnd);
            when(block.isInitialized()).thenReturn(initialized);
            when(block.isLoaded()).thenReturn(loaded);
            when(block.contains(any(Address.class))).thenAnswer(invocation -> {
                long address = ((Address) invocation.getArgument(0)).getOffset();
                return address >= start && address < start + bytes.length;
            });
            blocks.add(new BlockBytes(block, start, Arrays.copyOf(bytes, bytes.length)));
            when(memory.getBlocks()).thenAnswer(ignored ->
                    blocks.stream().map(BlockBytes::block).toArray(MemoryBlock[]::new));
            return block;
        }

        ListingService service() {
            return new ListingService(provider);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> result(Response response) {
        assertTrue(response.toJson(), response instanceof Response.Ok);
        return (Map<String, Object>) ((Response.Ok) response).data();
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> matches(Response response) {
        return (List<Map<String, Object>>) result(response).get("matches");
    }

    public void testInteriorSubstringHitIncludesDefinedDataAndBoundaryDiagnostics() throws Exception {
        Fixture fixture = new Fixture();
        byte[] bytes = "4>getattachtagname\0".getBytes(StandardCharsets.US_ASCII);
        fixture.addBlock(".rdata", 0x1000, bytes, true, true);

        Data containing = mock(Data.class);
        when(containing.getAddress()).thenReturn(SPACE.getAddress(0x1000));
        when(containing.getLength()).thenReturn(bytes.length);
        when(fixture.listing.getDefinedDataContaining(any(Address.class))).thenAnswer(invocation ->
                ((Address) invocation.getArgument(0)).getOffset() == 0x1002 ? containing : null);

        List<Map<String, Object>> found = matches(
                fixture.service().searchRawStrings("getattachtagname", "ascii", 0, 10, ""));

        assertEquals(1, found.size());
        assertTrue(found.get(0).get("address").toString().endsWith("1002"));
        Map<String, Object> boundary = (Map<String, Object>) found.get(0).get("boundary");
        assertEquals("3e", boundary.get("previous_byte_hex"));
        assertEquals("00", boundary.get("next_byte_hex"));
        assertEquals(Boolean.FALSE, boundary.get("at_block_start"));
        Map<String, Object> defined =
                (Map<String, Object>) found.get(0).get("containing_defined_data");
        assertEquals(2L, defined.get("byte_offset"));
        assertEquals(Boolean.FALSE, defined.get("match_at_start"));
        assertEquals(Boolean.TRUE, defined.get("match_fits"));
    }

    @SuppressWarnings("unchecked")
    public void testAllFindsAsciiAndUtf16AndSuppressesAsciiUtf8Duplicate() throws Exception {
        Fixture fixture = new Fixture();
        byte[] ascii = "needle\0".getBytes(StandardCharsets.US_ASCII);
        byte[] utf16 = "needle".getBytes(StandardCharsets.UTF_16LE);
        byte[] block = new byte[0x80];
        System.arraycopy(ascii, 0, block, 0x10, ascii.length);
        System.arraycopy(utf16, 0, block, 0x40, utf16.length);
        fixture.addBlock(".rdata", 0x2000, block, true, true);

        List<Map<String, Object>> found = matches(
                fixture.service().searchRawStrings("needle", "all", 0, 10, ""));

        assertEquals(2, found.size());
        Map<String, Object> asciiHit = found.stream()
                .filter(match -> "ascii".equals(match.get("encoding"))).findFirst().orElseThrow();
        assertEquals(List.of("ascii", "utf8"), asciiHit.get("equivalent_encodings"));
        assertTrue(found.stream().anyMatch(match -> "utf16le".equals(match.get("encoding"))));
    }

    public void testPaginationReportsTotalAndReturnsRequestedPage() throws Exception {
        Fixture fixture = new Fixture();
        fixture.addBlock(".rdata", 0x3000,
                "hit-hit-hit".getBytes(StandardCharsets.US_ASCII), true, true);

        Map<String, Object> result = result(
                fixture.service().searchRawStrings("hit", "ascii", 1, 1, ""));
        List<Map<String, Object>> found = matches(new Response.Ok(result));

        assertEquals(3, result.get("total_scanned"));
        assertEquals(1, result.get("returned"));
        assertTrue(found.get(0).get("address").toString().endsWith("3004"));
        assertEquals(Boolean.TRUE, result.get("total_is_exact"));
    }

    public void testSearchTermIsLiteralNotRegex() throws Exception {
        Fixture fixture = new Fixture();
        fixture.addBlock(".rdata", 0x3800,
                "a.b axb".getBytes(StandardCharsets.US_ASCII), true, true);

        List<Map<String, Object>> found = matches(
                fixture.service().searchRawStrings(".", "ascii", 0, 10, ""));

        assertEquals(1, found.size());
        assertTrue(found.get(0).get("address").toString().endsWith("3801"));
    }

    public void testInvalidInputsAreRejected() throws Exception {
        Fixture fixture = new Fixture();
        fixture.addBlock(".rdata", 0x4000, new byte[16], true, true);
        ListingService service = fixture.service();

        assertTrue(service.searchRawStrings("", "ascii", 0, 10, "") instanceof Response.Err);
        assertTrue(service.searchRawStrings("x", "utf32", 0, 10, "") instanceof Response.Err);
        assertTrue(service.searchRawStrings("x", "ascii", -1, 10, "") instanceof Response.Err);
        assertTrue(service.searchRawStrings("x", "ascii", 0, 0, "") instanceof Response.Err);
        assertTrue(service.searchRawStrings("x", "ascii", 100_000, 1, "") instanceof Response.Err);
        assertTrue(service.searchRawStrings("é", "ascii", 0, 10, "") instanceof Response.Err);
        assertTrue(service.searchRawStrings("\ud800", "utf8", 0, 10, "") instanceof Response.Err);
        assertTrue(service.searchRawStrings("x".repeat(1025), "utf8", 0, 10, "")
                instanceof Response.Err);
    }

    public void testUnloadedAndUninitializedBlocksAreExcluded() throws Exception {
        Fixture fixture = new Fixture();
        MemoryBlock eligible = fixture.addBlock("eligible", 0x5000,
                "needle".getBytes(StandardCharsets.US_ASCII), true, true);
        MemoryBlock uninitialized = fixture.addBlock("uninitialized", 0x6000,
                "needle".getBytes(StandardCharsets.US_ASCII), false, true);
        MemoryBlock unloaded = fixture.addBlock("unloaded", 0x7000,
                "needle".getBytes(StandardCharsets.US_ASCII), true, false);

        List<Map<String, Object>> found = matches(
                fixture.service().searchRawStrings("needle", "ascii", 0, 10, ""));

        assertEquals(1, found.size());
        assertEquals("eligible", found.get(0).get("block"));
        Address eligibleStart = eligible.getStart();
        Address eligibleEnd = eligible.getEnd();
        Address uninitializedStart = uninitialized.getStart();
        Address unloadedStart = unloaded.getStart();
        verify(fixture.memory, atLeastOnce()).findBytes(eq(eligibleStart), eq(eligibleEnd),
                any(byte[].class), isNull(), eq(true), any(TaskMonitor.class));
        verify(fixture.memory, never()).findBytes(eq(uninitializedStart), any(Address.class),
                any(byte[].class), any(), anyBoolean(), any(TaskMonitor.class));
        verify(fixture.memory, never()).findBytes(eq(unloadedStart), any(Address.class),
                any(byte[].class), any(), anyBoolean(), any(TaskMonitor.class));
    }

    public void testSearchPerformsNoMemoryWrites() throws Exception {
        Fixture fixture = new Fixture();
        fixture.addBlock(".rdata", 0x8000,
                "needle".getBytes(StandardCharsets.US_ASCII), true, true);

        fixture.service().searchRawStrings("needle", "all", 0, 10, "");

        verify(fixture.memory, never()).setByte(any(Address.class), anyByte());
        verify(fixture.memory, never()).setBytes(any(Address.class), any(byte[].class));
        verify(fixture.memory, never()).setBytes(any(Address.class), any(byte[].class), anyInt(), anyInt());
    }
}
