package com.s2tool.core;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Target 单元测试：URL 解析逻辑。
 */
public class TargetTest {

    @Test
    public void testNormalizeWithoutScheme() {
        Target t = new Target("example.com:8080/upload.action");
        assertEquals("http", t.getScheme());
        assertEquals("example.com", t.getHost());
        assertEquals(8080, t.getPort());
        assertEquals("/upload.action", t.getPath());
    }

    @Test
    public void testFullUrlWithPath() {
        Target t = new Target("https://example.com:8443/app/upload.action");
        assertEquals("https", t.getScheme());
        assertEquals("example.com", t.getHost());
        assertEquals(8443, t.getPort());
        assertEquals("/app/upload.action", t.getPath());
        assertEquals("https://example.com:8443/app/upload.action", t.getFullUrl());
    }

    @Test
    public void testDefaultPorts() {
        Target t1 = new Target("http://example.com/");
        assertEquals(80, t1.getPort());
        Target t2 = new Target("https://example.com/");
        assertEquals(443, t2.getPort());
    }

    @Test
    public void testRootPathDefaults() {
        Target t = new Target("http://example.com");
        assertEquals("/", t.getPath());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEmptyUrl() {
        new Target("");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidHost() {
        new Target("http:///path");
    }

    @Test
    public void testCookieAndAuth() {
        Target t = new Target("http://example.com/");
        t.setCookie("JSESSIONID=abc123");
        assertEquals("JSESSIONID=abc123", t.getCookie());
        t.setBasicAuth("admin", "pass");
        assertTrue(t.hasBasicAuth());
        assertEquals("admin", t.getBasicAuthUser());
        assertEquals("pass", t.getBasicAuthPass());
    }
}
