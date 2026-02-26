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
package reva.util;

import static org.junit.Assert.*;

import org.junit.Test;

/**
 * Test class for MemoryUtil utility methods.
 */
public class MemoryUtilTest {

    // ========================================================================
    // parseHexPattern tests
    // ========================================================================

    @Test
    public void testParseHexPattern_SpaceSeparated() {
        MemoryUtil.HexPattern result = MemoryUtil.parseHexPattern("4D 5A 90 00");

        assertEquals(4, result.bytes().length);
        assertEquals((byte) 0x4D, result.bytes()[0]);
        assertEquals((byte) 0x5A, result.bytes()[1]);
        assertEquals((byte) 0x90, result.bytes()[2]);
        assertEquals((byte) 0x00, result.bytes()[3]);

        // All masks should be 0xFF (exact match)
        for (byte mask : result.masks()) {
            assertEquals((byte) 0xFF, mask);
        }
    }

    @Test
    public void testParseHexPattern_Concatenated() {
        MemoryUtil.HexPattern result = MemoryUtil.parseHexPattern("4D5A9000");

        assertEquals(4, result.bytes().length);
        assertEquals((byte) 0x4D, result.bytes()[0]);
        assertEquals((byte) 0x5A, result.bytes()[1]);
        assertEquals((byte) 0x90, result.bytes()[2]);
        assertEquals((byte) 0x00, result.bytes()[3]);

        for (byte mask : result.masks()) {
            assertEquals((byte) 0xFF, mask);
        }
    }

    @Test
    public void testParseHexPattern_WithWildcards() {
        MemoryUtil.HexPattern result = MemoryUtil.parseHexPattern("4D ?? 90 00");

        assertEquals(4, result.bytes().length);
        assertEquals((byte) 0x4D, result.bytes()[0]);
        assertEquals((byte) 0x00, result.bytes()[1]); // wildcard data byte
        assertEquals((byte) 0x90, result.bytes()[2]);
        assertEquals((byte) 0x00, result.bytes()[3]);

        assertEquals((byte) 0xFF, result.masks()[0]); // exact match
        assertEquals((byte) 0x00, result.masks()[1]); // wildcard
        assertEquals((byte) 0xFF, result.masks()[2]); // exact match
        assertEquals((byte) 0xFF, result.masks()[3]); // exact match
    }

    @Test
    public void testParseHexPattern_MixedCase() {
        MemoryUtil.HexPattern result = MemoryUtil.parseHexPattern("4d 5a");

        assertEquals(2, result.bytes().length);
        assertEquals((byte) 0x4D, result.bytes()[0]);
        assertEquals((byte) 0x5A, result.bytes()[1]);
    }

    @Test
    public void testParseHexPattern_SingleByte() {
        MemoryUtil.HexPattern result = MemoryUtil.parseHexPattern("FF");

        assertEquals(1, result.bytes().length);
        assertEquals((byte) 0xFF, result.bytes()[0]);
        assertEquals((byte) 0xFF, result.masks()[0]);
    }

    @Test
    public void testParseHexPattern_AllWildcards() {
        MemoryUtil.HexPattern result = MemoryUtil.parseHexPattern("?? ?? ??");

        assertEquals(3, result.bytes().length);
        for (int i = 0; i < 3; i++) {
            assertEquals((byte) 0x00, result.bytes()[i]);
            assertEquals((byte) 0x00, result.masks()[i]);
        }
    }

    @Test
    public void testParseHexPattern_ConcatenatedWithWildcard() {
        MemoryUtil.HexPattern result = MemoryUtil.parseHexPattern("4D??90");

        assertEquals(3, result.bytes().length);
        assertEquals((byte) 0x4D, result.bytes()[0]);
        assertEquals((byte) 0x00, result.bytes()[1]);
        assertEquals((byte) 0x90, result.bytes()[2]);

        assertEquals((byte) 0xFF, result.masks()[0]);
        assertEquals((byte) 0x00, result.masks()[1]);
        assertEquals((byte) 0xFF, result.masks()[2]);
    }

    @Test
    public void testParseHexPattern_ExtraWhitespace() {
        MemoryUtil.HexPattern result = MemoryUtil.parseHexPattern("  4D  5A  ");

        assertEquals(2, result.bytes().length);
        assertEquals((byte) 0x4D, result.bytes()[0]);
        assertEquals((byte) 0x5A, result.bytes()[1]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testParseHexPattern_NullInput() {
        MemoryUtil.parseHexPattern(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testParseHexPattern_EmptyString() {
        MemoryUtil.parseHexPattern("");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testParseHexPattern_WhitespaceOnly() {
        MemoryUtil.parseHexPattern("   ");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testParseHexPattern_OddLength() {
        MemoryUtil.parseHexPattern("4D5");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testParseHexPattern_InvalidHexChars() {
        MemoryUtil.parseHexPattern("4D GH");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testParseHexPattern_InvalidCharInConcatenated() {
        MemoryUtil.parseHexPattern("4DXY90");
    }

    // ========================================================================
    // formatHexString tests
    // ========================================================================

    @Test
    public void testFormatHexString_NormalBytes() {
        byte[] bytes = {(byte) 0x4D, (byte) 0x5A, (byte) 0x90, (byte) 0x00};
        String result = MemoryUtil.formatHexString(bytes);
        assertEquals("4D 5A 90 00", result);
    }

    @Test
    public void testFormatHexString_EmptyArray() {
        String result = MemoryUtil.formatHexString(new byte[0]);
        assertEquals("", result);
    }

    @Test
    public void testFormatHexString_NullArray() {
        String result = MemoryUtil.formatHexString(null);
        assertEquals("", result);
    }

    // ========================================================================
    // byteArrayToIntList tests
    // ========================================================================

    @Test
    public void testByteArrayToIntList_NormalBytes() {
        byte[] bytes = {(byte) 0x00, (byte) 0x7F, (byte) 0x80, (byte) 0xFF};
        java.util.List<Integer> result = MemoryUtil.byteArrayToIntList(bytes);
        assertEquals(4, result.size());
        assertEquals(Integer.valueOf(0), result.get(0));
        assertEquals(Integer.valueOf(127), result.get(1));
        assertEquals(Integer.valueOf(128), result.get(2));
        assertEquals(Integer.valueOf(255), result.get(3));
    }

    @Test
    public void testByteArrayToIntList_EmptyArray() {
        java.util.List<Integer> result = MemoryUtil.byteArrayToIntList(new byte[0]);
        assertTrue(result.isEmpty());
    }

    @Test
    public void testByteArrayToIntList_NullArray() {
        java.util.List<Integer> result = MemoryUtil.byteArrayToIntList(null);
        assertTrue(result.isEmpty());
    }
}
