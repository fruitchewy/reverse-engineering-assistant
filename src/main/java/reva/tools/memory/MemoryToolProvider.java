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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.MemoryUtil;
import reva.util.SchemaUtil;

/**
 * Tool provider for memory-related operations.
 * Provides tools to list memory blocks, read memory content, and search for byte patterns.
 */
public class MemoryToolProvider extends AbstractToolProvider {

    private static final int DEFAULT_MAX_RESULTS = 100;
    private static final int MAX_RESULTS_LIMIT = 10000;

    /**
     * Constructor
     * @param server The MCP server
     */
    public MemoryToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerMemoryBlocksTool();
        registerReadMemoryTool();
        registerSearchMemoryTool();
    }

    /**
     * Register a tool to list memory blocks from a program
     */
    private void registerMemoryBlocksTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path to the program in the Ghidra Project"));

        List<String> required = List.of("programPath");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-memory-blocks")
            .title("Get Memory Blocks")
            .description("Get memory blocks from the selected program")
            .inputSchema(createSchema(properties, required))
            .build();

        // Add the tool using the parent's method
        super.registerTool(tool, (exchange, request) -> {
            // Get program using helper method
            Program program = getProgramFromArgs(request);

            // Get the memory from the program
            Memory memory = program.getMemory();
            List<Map<String, Object>> blockData = new ArrayList<>();

            // Iterate through all memory blocks
            for (MemoryBlock block : memory.getBlocks()) {
                Map<String, Object> blockInfo = new HashMap<>();
                blockInfo.put("name", block.getName());
                blockInfo.put("start", block.getStart().toString());
                blockInfo.put("end", block.getEnd().toString());
                blockInfo.put("size", block.getSize());
                blockInfo.put("readable", block.isRead());
                blockInfo.put("writable", block.isWrite());
                blockInfo.put("executable", block.isExecute());
                blockInfo.put("initialized", block.isInitialized());
                blockInfo.put("volatile", block.isVolatile());
                blockInfo.put("mapped", block.isMapped());
                blockInfo.put("overlay", block.isOverlay());

                blockData.add(blockInfo);
            }

            return createJsonResult(blockData);
        });
    }

    /**
     * Register a tool to read memory content from a program
     */
    private void registerReadMemoryTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path to the program in the Ghidra Project"));
        properties.put("addressOrSymbol", SchemaUtil.stringProperty("Address or symbol name to read from (e.g. '00400000' or 'main')"));
        properties.put("length", SchemaUtil.integerPropertyWithDefault("Number of bytes to read", 16));
        properties.put("format", SchemaUtil.stringPropertyWithDefault("Output format: 'hex', 'bytes', or 'both'", "hex"));

        List<String> required = List.of("programPath", "addressOrSymbol");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("read-memory")
            .title("Read Memory")
            .description("Read memory at a specific address")
            .inputSchema(createSchema(properties, required))
            .build();

        // Add the tool using the parent's method
        super.registerTool(tool, (exchange, request) -> {
            // Get program and address using helper methods
            Program program = getProgramFromArgs(request);
            Address address = getAddressFromArgs(request, program, "addressOrSymbol");

            // Get the length from the request
            int length = getOptionalInt(request, "length", 16);
            if (length <= 0) {
                return createErrorResult("Invalid length: " + length);
            }

            // Get the format from the request
            String format = getOptionalString(request, "format", "hex");

            // Read the memory
            byte[] bytes = MemoryUtil.readMemoryBytes(program, address, length);
            if (bytes == null) {
                return createErrorResult("Memory access error at address: " + address);
            }

            // Format the result
            Map<String, Object> result = new HashMap<>();
            result.put("address", address.toString());
            result.put("length", bytes.length);

            if ("hex".equals(format) || "both".equals(format)) {
                result.put("hex", MemoryUtil.formatHexString(bytes));
            }

            if ("bytes".equals(format) || "both".equals(format)) {
                result.put("bytes", MemoryUtil.byteArrayToIntList(bytes));
            }

            return createJsonResult(result);
        });
    }

    /**
     * Register a tool to search memory for byte patterns
     */
    private void registerSearchMemoryTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path to the program in the Ghidra Project"));
        properties.put("pattern", SchemaUtil.stringProperty(
            "Hex byte pattern to search for. Space-separated or concatenated. " +
            "Use '??' for wildcard bytes. Examples: '4D 5A 90 00', '4D5A??00'"));
        properties.put("startAddress", SchemaUtil.stringProperty(
            "Address or symbol to start searching from (default: program minimum address)"));
        properties.put("endAddress", SchemaUtil.stringProperty(
            "Address or symbol to stop searching at (default: program maximum address)"));
        properties.put("blockName", SchemaUtil.stringProperty(
            "Restrict search to a specific memory block by name"));
        properties.put("maxResults", SchemaUtil.integerPropertyWithDefault(
            "Maximum number of results to return", DEFAULT_MAX_RESULTS));
        properties.put("alignment", SchemaUtil.integerPropertyWithDefault(
            "Byte alignment for search (1 = every byte, 4 = dword-aligned, etc.)", 1));

        List<String> required = List.of("programPath", "pattern");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("search-memory")
            .title("Search Memory")
            .description("Search program memory for a hex byte pattern. Supports wildcard bytes " +
                "with '??'. Useful for finding byte signatures, magic values, strings, or " +
                "specific instruction sequences.")
            .inputSchema(createSchema(properties, required))
            .build();

        super.registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            String patternStr = getString(request, "pattern");

            // Parse the hex pattern
            MemoryUtil.HexPattern hexPattern;
            try {
                hexPattern = MemoryUtil.parseHexPattern(patternStr);
            } catch (IllegalArgumentException e) {
                return createErrorResult("Invalid hex pattern: " + e.getMessage());
            }

            int maxResults = getOptionalInt(request, "maxResults", DEFAULT_MAX_RESULTS);
            if (maxResults <= 0) {
                maxResults = DEFAULT_MAX_RESULTS;
            }
            maxResults = Math.min(maxResults, MAX_RESULTS_LIMIT);

            int alignment = getOptionalInt(request, "alignment", 1);
            if (alignment <= 0) {
                return createErrorResult("Alignment must be a positive integer, got: " + alignment);
            }

            // Determine search address range
            Memory memory = program.getMemory();
            Address searchStart;
            Address searchEnd;

            String blockName = getOptionalString(request, "blockName", null);
            if (blockName != null && !blockName.isEmpty()) {
                // Restrict to a specific memory block
                MemoryBlock block = MemoryUtil.findBlockByName(program, blockName);
                if (block == null) {
                    return createErrorResult("Memory block not found: " + blockName);
                }
                searchStart = block.getStart();
                searchEnd = block.getEnd();
            } else {
                // Use explicit start/end or full program range
                String startStr = getOptionalString(request, "startAddress", null);
                String endStr = getOptionalString(request, "endAddress", null);

                searchStart = (startStr != null && !startStr.isEmpty())
                    ? AddressUtil.resolveAddressOrSymbol(program, startStr)
                    : program.getMinAddress();
                searchEnd = (endStr != null && !endStr.isEmpty())
                    ? AddressUtil.resolveAddressOrSymbol(program, endStr)
                    : program.getMaxAddress();

                if (searchStart == null) {
                    return createErrorResult("Invalid start address or symbol: " + startStr);
                }
                if (searchEnd == null) {
                    return createErrorResult("Invalid end address or symbol: " + endStr);
                }
            }

            // Search for the pattern
            List<Map<String, Object>> results = new ArrayList<>();
            Address currentAddr = searchStart;
            int patternLength = hexPattern.bytes().length;

            while (results.size() < maxResults) {
                Address found = memory.findBytes(currentAddr, searchEnd,
                    hexPattern.bytes(), hexPattern.masks(), true, alignment);

                if (found == null) {
                    break;
                }

                Map<String, Object> matchResult = new HashMap<>();
                matchResult.put("address", AddressUtil.formatAddress(found));

                // Read the actual matched bytes
                byte[] matchedBytes = MemoryUtil.readMemoryBytes(program, found, patternLength);
                if (matchedBytes != null) {
                    matchResult.put("matchedBytes", MemoryUtil.formatHexString(matchedBytes));
                }

                // Include memory block info
                MemoryBlock containingBlock = memory.getBlock(found);
                if (containingBlock != null) {
                    matchResult.put("blockName", containingBlock.getName());
                }

                // Include function context if available
                Function func = program.getFunctionManager().getFunctionContaining(found);
                if (func != null) {
                    matchResult.put("function", func.getName());
                    matchResult.put("functionAddress", AddressUtil.formatAddress(func.getEntryPoint()));
                }

                results.add(matchResult);

                // Advance past this match
                try {
                    currentAddr = found.add(1);
                } catch (Exception e) {
                    break; // Address overflow, we've reached the end
                }
            }

            Map<String, Object> response = new HashMap<>();
            response.put("programPath", program.getDomainFile().getPathname());
            response.put("pattern", patternStr);
            response.put("resultCount", results.size());
            response.put("truncated", results.size() >= maxResults);
            response.put("results", results);

            return createJsonResult(response);
        });
    }

}
