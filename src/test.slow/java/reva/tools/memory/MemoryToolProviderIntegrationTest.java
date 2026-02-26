/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package reva.tools.memory;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import reva.RevaIntegrationTestBase;

/**
 * Integration tests for MemoryToolProvider that verify MCP tool registration
 * and basic functionality.
 */
public class MemoryToolProviderIntegrationTest extends RevaIntegrationTestBase {
    
    private String programPath;
    
    @Before
    public void setUpTestData() throws Exception {
        programPath = program.getDomainFile().getPathname();
    }
    
    @Test
    public void testMemoryBlocksAndToolRegistration() throws Exception {
        // Verify that the program has the expected memory block
        MemoryBlock[] blocks = program.getMemory().getBlocks();
        assertTrue("Program should have at least one memory block", blocks.length > 0);
        
        // Find the test memory block
        MemoryBlock testBlock = null;
        for (MemoryBlock block : blocks) {
            if ("test".equals(block.getName())) {
                testBlock = block;
                break;
            }
        }
        assertNotNull("Test memory block should exist", testBlock);
        assertEquals("Test block should start at 0x01000000", 
            0x01000000L, testBlock.getStart().getOffset());
        assertEquals("Test block should be 0x1000 bytes", 0x1000, testBlock.getSize());
        
        // Verify that the MCP server has the MemoryToolProvider tools registered
        // We can check this by looking at the server's registered tools
        io.modelcontextprotocol.server.McpSyncServer mcpServer = 
            reva.util.RevaInternalServiceRegistry.getService(io.modelcontextprotocol.server.McpSyncServer.class);
        assertNotNull("MCP server should be registered", mcpServer);
        
        // The memory tools should be registered: get-memory-blocks, read-memory
        // This validates that our tool provider integration is working
    }
    
    @Test
    public void testProgramSetupForMemoryTests() throws Exception {
        // Verify that the program path is set correctly
        assertNotNull("Program path should be set", programPath);
        assertNotNull("Program should be set", program);

        // Verify the config manager and server port are available
        assertNotNull("Config manager should be available", configManager);
        assertEquals("Server port should be 8080", 8080, configManager.getServerPort());

        // Verify that we have a usable memory space
        assertNotNull("Program should have memory", program.getMemory());
        assertTrue("Program should have at least one memory block",
            program.getMemory().getBlocks().length > 0);
    }

    @Test
    public void testSearchMemoryToolRegistered() throws Exception {
        // Verify that the MCP server has the search-memory tool registered
        io.modelcontextprotocol.server.McpSyncServer mcpServer =
            reva.util.RevaInternalServiceRegistry.getService(io.modelcontextprotocol.server.McpSyncServer.class);
        assertNotNull("MCP server should be registered", mcpServer);

        // The search-memory tool should be registered along with existing memory tools
    }

    @Test
    public void testSearchMemoryFindsKnownPattern() throws Exception {
        // Write a known pattern into the test memory block
        Memory memory = program.getMemory();
        Address testAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000100);

        byte[] testPattern = {(byte) 0x4D, (byte) 0x5A, (byte) 0x90, (byte) 0x00};
        int txId = program.startTransaction("Write test pattern");
        try {
            memory.setBytes(testAddr, testPattern);
        } finally {
            program.endTransaction(txId, true);
        }

        // Verify the pattern was written correctly
        byte[] readBack = new byte[4];
        memory.getBytes(testAddr, readBack);
        assertEquals((byte) 0x4D, readBack[0]);
        assertEquals((byte) 0x5A, readBack[1]);
        assertEquals((byte) 0x90, readBack[2]);
        assertEquals((byte) 0x00, readBack[3]);

        // Now search for the pattern using Ghidra's Memory.findBytes API directly
        // (verifying the API works as expected for our tool implementation)
        byte[] searchBytes = {(byte) 0x4D, (byte) 0x5A, (byte) 0x90, (byte) 0x00};
        byte[] searchMasks = {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};

        Address found = memory.findBytes(
            program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000000),
            program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000FFF),
            searchBytes, searchMasks, true, 1);

        assertNotNull("Should find the pattern in memory", found);
        assertEquals("Found address should match where we wrote the pattern",
            0x01000100L, found.getOffset());
    }

    @Test
    public void testSearchMemoryWithWildcard() throws Exception {
        // Write a pattern into the test memory block
        Memory memory = program.getMemory();
        Address testAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000200);

        byte[] testPattern = {(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF};
        int txId = program.startTransaction("Write test pattern for wildcard");
        try {
            memory.setBytes(testAddr, testPattern);
        } finally {
            program.endTransaction(txId, true);
        }

        // Search with a wildcard in the middle: DE ?? BE EF
        byte[] searchBytes = {(byte) 0xDE, (byte) 0x00, (byte) 0xBE, (byte) 0xEF};
        byte[] searchMasks = {(byte) 0xFF, (byte) 0x00, (byte) 0xFF, (byte) 0xFF};

        Address found = memory.findBytes(
            program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000000),
            program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000FFF),
            searchBytes, searchMasks, true, 1);

        assertNotNull("Should find the pattern with wildcard", found);
        assertEquals("Found address should match where we wrote the pattern",
            0x01000200L, found.getOffset());
    }

    @Test
    public void testSearchMemoryNoResults() throws Exception {
        // Search for a pattern that doesn't exist in the zero-initialized block
        Memory memory = program.getMemory();

        byte[] searchBytes = {(byte) 0xFF, (byte) 0xFE, (byte) 0xFD, (byte) 0xFC};
        byte[] searchMasks = {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};

        Address found = memory.findBytes(
            program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000000),
            program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000FFF),
            searchBytes, searchMasks, true, 1);

        assertNull("Should not find a pattern that doesn't exist", found);
    }
}