package com.s2tool.core;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * ResultParser 单元测试。
 */
public class ResultParserTest {

    @Test
    public void testContains() {
        assertTrue(ResultParser.contains("abc123def", "123"));
        assertFalse(ResultParser.contains("abc", "xyz"));
        assertFalse(ResultParser.contains(null, "x"));
    }

    @Test
    public void testContainsAnywhere() {
        Map<String, String> headers = new HashMap<>();
        headers.put("X-Test", "marker123");
        HttpResponseData resp = new HttpResponseData(200, headers, "body", new byte[0], 100, null);
        assertTrue(ResultParser.containsAnywhere(resp, "marker123"));
        assertFalse(ResultParser.containsAnywhere(resp, "nothere"));
    }

    @Test
    public void testHasStrutsError() {
        HttpResponseData resp = new HttpResponseData(500,
                new HashMap<>(), "org.apache.struts2.ServletActionContext error", new byte[0], 100, null);
        assertTrue(ResultParser.hasStrutsError(resp));
    }

    @Test
    public void testHasJakartaError() {
        HttpResponseData resp = new HttpResponseData(500, new HashMap<>(),
                "the request doesn't contain a multipart/form-data or multipart/mixed stream",
                new byte[0], 100, null);
        assertTrue(ResultParser.hasJakartaError(resp));
    }

    @Test
    public void testIsDelayExceeded() {
        assertTrue(ResultParser.isDelayExceeded(8000, 1000, 5000));
        assertFalse(ResultParser.isDelayExceeded(2000, 1000, 5000));
    }

    @Test
    public void testExtract() {
        String body = "prefix=[TARGET_VALUE]suffix";
        assertEquals("TARGET_VALUE", ResultParser.extract(body, "\\[([^\\]]+)\\]"));
    }
}
