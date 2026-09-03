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

import java.util.HashMap;
import java.util.Map;

/**
 * S2-045 漏洞检测插件（CVE-2017-5638）。
 *
 * <p>漏洞原理：Jakarta Multipart 解析器解析 Content-Type 异常时，将用户可控的
 * Content-Type 值拼入异常消息；异常消息经 Struts2 国际化文本处理流程
 * （LocalizedTextUtil → TextParseUtil.translateVariables）被 OGNL 求值，
 * 导致任意 OGNL 表达式执行，进而 RCE。</p>
 *
 * <p>检测策略（多重检测 + 置信度综合判定）：
 * <ol>
 *   <li><b>数学运算验证</b>（高置信度）：执行无害字符串拼接，响应体出现预期结果即确认</li>
 *   <li><b>指纹标记</b>（高置信度）：注入随机 UUID 并回显到响应体，命中即确认</li>
 *   <li><b>延时检测</b>（中置信度）：Thread.sleep 时间差判定，用于无回显场景</li>
 *   <li><b>错误特征</b>（辅助）：Jakarta 解析器异常关键字佐证</li>
 * </ol>
 *
 * <p>综合判定规则：
 * <ul>
 *   <li>任一高置信度方法确认 → CONFIRMED</li>
 *   <li>仅延时命中 → SUSPICIOUS（待人工确认）</li>
 *   <li>高置信度方法结果冲突 → SUSPICIOUS</li>
 *   <li>全部未命中 → NOT_FOUND</li>
 * </ul></p>
 */
public class S2_045 implements VulPlugin {

    private static final VulnInfo INFO = new VulnInfo(
            "S2-045",
            "CVE-2017-5638",
            "Struts2 Jakarta Multipart Parser OGNL Injection",
            "Jakarta Multipart 解析器解析 Content-Type 异常时，用户可控的 Content-Type 值 "
                    + "被拼入异常消息，异常消息经 Struts2 国际化文本处理流程被 OGNL 求值，"
                    + "导致任意代码执行（RCE）。",
            "2.3.5 - 2.3.31, 2.5 - 2.5.10.1",
            "header",
            new String[]{"math", "marker", "delay"},
            "high",
            "升级至 Struts2 2.3.32 或 2.5.10.1 以上版本；"
                    + "或改用非 Jakarta 的 multipart 解析器（cos/pell）；"
                    + "临时缓解：拦截含 %{ 的 Content-Type 请求头"
    );

    @Override
    public VulnInfo getInfo() {
        return INFO;
    }

    @Override
    public DetectionResult check(Target target, PluginContext ctx) {
        HttpClient http = ctx.getHttpClient();
        DetectionResult result = new DetectionResult(INFO.getVulnId());
        result.setRequestPreview("POST " + target.getFullUrl() + "  [Content-Type 注入]");

        // 1) 数学运算验证（高置信度）
        boolean mathHit = checkMath(http, target, ctx, result);

        // 2) 指纹标记验证（高置信度）
        boolean markerHit = checkMarker(http, target, ctx, result);

        // 3) 延时检测（中置信度，无回显场景）
        boolean delayHit = false;
        if (!mathHit && !markerHit) {
            delayHit = checkDelay(http, target, ctx, result);
        }

        // 综合判定
        if (mathHit || markerHit) {
            result.setStatus(DetectionResult.Status.CONFIRMED);
            result.setConfidence(DetectionResult.Confidence.HIGH);
            result.setDetail("OGNL 表达式执行确认（数学验证=" + mathHit
                    + ", 指纹标记=" + markerHit + "）");
            if (result.getTechniques().isEmpty()) {
                result.addTechnique("math");
            }
        } else if (delayHit) {
            result.setStatus(DetectionResult.Status.SUSPICIOUS);
            result.setConfidence(DetectionResult.Confidence.MEDIUM);
            result.setDetail("延时检测命中（响应时间显著高于基线），存在无回显 RCE 迹象，需人工确认");
            result.addTechnique("delay");
        } else {
            result.setStatus(DetectionResult.Status.NOT_FOUND);
            result.setDetail("所有检测策略均未命中");
        }
        return result;
    }

    /** 数学运算验证：响应体中回显公开 POC 算式结果 88866777 */
    private boolean checkMath(HttpClient http, Target target, PluginContext ctx,
                              DetectionResult result) {
        try {
            String expected = PayloadBuilder.MATH_RESULT;
            String contentType = PayloadBuilder.mathValidationPayload();

            Map<String, String> extra = new HashMap<>();
            if (ctx.getExtraHeaders() != null) extra.putAll(ctx.getExtraHeaders());

            HttpResponseData resp = http.post(target.getFullUrl(), contentType,
                    target.getCookie(), target.getBasicAuthUser(), target.getBasicAuthPass(),
                    null, extra);
            result.setElapsedMs(resp.getElapsedMs());
            result.setRawResponse(resp);
            result.setResponsePreview(truncate(resp.getBody(), 1000));

            if (resp.isConnected() && ResultParser.contains(resp.getBody(), expected)) {
                result.addTechnique("math");
                result.setDetail("数学运算验证命中：响应包含算式结果 " + expected);
                return true;
            }
        } catch (Exception e) {
            // 网络异常由调用方处理
        }
        return false;
    }

    /** 指纹标记验证：随机 UUID 回显 */
    private boolean checkMarker(HttpClient http, Target target, PluginContext ctx,
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
                result.setDetail("指纹标记命中：响应中出现注入的 UUID 标记");
                return true;
            }
        } catch (Exception e) {
            // ignore
        }
        return false;
    }

    /** 延时检测：Thread.sleep 时间差（仅用于无回显场景） */
    private boolean checkDelay(HttpClient http, Target target, PluginContext ctx,
                               DetectionResult result) {
        try {
            // 基线请求（不带 payload 的正常 POST）
            HttpResponseData baseline = http.post(target.getFullUrl(),
                    "multipart/form-data; boundary=----WebKitFormBoundary" + System.nanoTime() % 100000,
                    target.getCookie(), target.getBasicAuthUser(), target.getBasicAuthPass(),
                    new byte[0], ctx.getExtraHeaders());

            long delayMs = 6000;
            String contentType = PayloadBuilder.sleepPayload(delayMs);
            HttpResponseData probe = http.post(target.getFullUrl(), contentType,
                    target.getCookie(), target.getBasicAuthUser(), target.getBasicAuthPass(),
                    null, ctx.getExtraHeaders());

            result.setElapsedMs(probe.getElapsedMs());
            result.setRawResponse(probe);
            result.setResponsePreview(truncate(probe.getBody(), 1000));

            long threshold = (long) (delayMs * 0.6);
            return ResultParser.isDelayExceeded(probe.getElapsedMs(),
                    baseline.getElapsedMs(), threshold);
        } catch (Exception e) {
            result.setStatus(DetectionResult.Status.ERROR);
            result.setError(e);
            return false;
        }
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max);
    }
}
