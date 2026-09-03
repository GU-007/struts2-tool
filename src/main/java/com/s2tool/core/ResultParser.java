package com.s2tool.core;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 响应解析与判定工具：从 HTTP 响应中提取关键特征，辅助漏洞判定。
 *
 * <p>支持：关键字搜索、Struts2 错误特征匹配、响应体长度统计、
 * 时间差判定等。</p>
 */
public final class ResultParser {

    /** Struts2 / OGNL 相关错误特征关键字 */
    public static final String[] STRUTS_ERROR_KEYWORDS = {
            "org.apache.struts2",
            "ognl.OgnlException",
            "ognl.ExpressionSyntaxException",
            "NoSuchMethodException",
            "com.opensymphony.xwork2",
            "Struts Problem Report",
            "there is no Action mapped for namespace",
            "freemarker",
            "java.lang.RuntimeException",
            "Unable to find class",
            "com.opensymphony.xwork2.util.TextParseUtil"
    };

    /** Jakarta multipart 解析器异常特征 */
    public static final String[] JAKARTA_ERROR_KEYWORDS = {
            "the request doesn't contain a multipart/form-data",
            "content type header is",
            "org.apache.commons.fileupload",
            "InvalidContentTypeException"
    };

    private ResultParser() {}

    /**
     * 在响应体中搜索指定标记（精确匹配）。
     */
    public static boolean contains(String body, String marker) {
        return body != null && marker != null && body.contains(marker);
    }

    /**
     * 在响应体或响应头中搜索标记（指纹标记高精度判定）。
     */
    public static boolean containsAnywhere(HttpResponseData resp, String marker) {
        if (marker == null || marker.isEmpty()) return false;
        if (contains(resp.getBody(), marker)) return true;
        for (String v : resp.getHeaders().values()) {
            if (v != null && v.contains(marker)) return true;
        }
        return false;
    }

    /**
     * 检查响应中是否包含任一 Struts2 错误特征关键字。
     */
    public static boolean hasStrutsError(HttpResponseData resp) {
        String body = resp.getBody();
        if (body == null) return false;
        for (String kw : STRUTS_ERROR_KEYWORDS) {
            if (body.contains(kw)) return true;
        }
        return false;
    }

    /**
     * 检查响应中是否包含 Jakarta multipart 解析器异常特征。
     */
    public static boolean hasJakartaError(HttpResponseData resp) {
        String body = resp.getBody();
        if (body == null) return false;
        for (String kw : JAKARTA_ERROR_KEYWORDS) {
            if (body.contains(kw)) return true;
        }
        return false;
    }

    /**
     * 通过正则从响应体中提取匹配内容（用于命令执行结果提取）。
     */
    public static String extract(String body, String regex) {
        if (body == null) return null;
        Matcher m = Pattern.compile(regex, Pattern.DOTALL).matcher(body);
        return m.find() ? m.group(1) : null;
    }

    /**
     * 统计响应体字节长度。
     */
    public static int bodyLength(HttpResponseData resp) {
        return resp.getBodyBytes().length;
    }

    /**
     * 时间差是否超过阈值（延时检测）。
     *
     * @param probeMs   探测请求耗时
     * @param baselineMs 基线请求耗时
     * @param thresholdMs 判定阈值
     */
    public static boolean isDelayExceeded(long probeMs, long baselineMs, long thresholdMs) {
        return (probeMs - baselineMs) >= thresholdMs;
    }
}
