package com.s2tool.modules;

import com.s2tool.core.HttpClient;
import com.s2tool.core.HttpResponseData;
import com.s2tool.core.Target;

import java.util.ArrayList;
import java.util.List;

/**
 * Struts2 框架指纹识别器。
 *
 * <p>两级识别：
 * <ul>
 *   <li>第一层：框架识别（是否为 Struts2）——URL 后缀、静态资源、响应头、错误关键字</li>
 *   <li>第二层：版本范围粗识别——基于特征推断 2.0.x / 2.1.x / 2.3.x / 2.5.x</li>
 * </ul></p>
 */
public class Fingerprinter {

    /** Struts2 静态资源特征路径 */
    private static final String[] STATIC_RESOURCES = {
            "/struts/struts-tags.tld",
            "/struts/domTT.css",
            "/struts/xhtml/styles.css",
            "/struts/utils.js",
            "/struts/xhtml/validation.css"
    };

    /** Struts2 / OGNL 特征关键字（错误页） */
    private static final String[] FRAMEWORK_KEYWORDS = {
            "org.apache.struts2",
            "com.opensymphony.xwork2",
            "struts2",
            "Struts Problem Report",
            "ognl.OgnlException"
    };

    /** 版本特征 */
    private static final String[] VERSION_KEYWORDS = {
            "struts2-core-2.5",
            "struts2-core-2.3",
            "struts2-core-2.1",
            "struts2-core-2.0",
            "org.apache.struts2:struts2-core:2.5",
            "org.apache.struts2:struts2-core:2.3",
            "struts-2.5",
            "struts-2.3"
    };

    private final HttpClient http;

    public Fingerprinter(HttpClient http) {
        this.http = http;
    }

    /**
     * 对目标执行指纹识别。
     *
     * @return 识别结果（framework / versionRange / detectedBy）
     */
    public FingerprintResult fingerprint(Target target) {
        FingerprintResult result = new FingerprintResult();
        result.target = target.getFullUrl();

        // 1) URL 后缀识别
        String path = target.getPath().toLowerCase();
        if (path.endsWith(".action") || path.endsWith(".do") || path.contains(".action;")) {
            result.isStruts2 = true;
            result.detectedBy.add("url_suffix");
        }

        // 2) 发送一个畸形请求观察错误页特征
        HttpResponseData probe = sendProbe(target);
        if (probe.isConnected()) {
            String body = probe.getBody();
            for (String kw : FRAMEWORK_KEYWORDS) {
                if (body != null && body.toLowerCase().contains(kw.toLowerCase())) {
                    result.isStruts2 = true;
                    result.detectedBy.add("error_page_keyword:" + kw);
                    break;
                }
            }
            // 版本特征
            for (String vk : VERSION_KEYWORDS) {
                if (body != null && body.contains(vk)) {
                    result.versionRange = inferVersion(vk);
                    result.detectedBy.add("version_keyword:" + vk);
                    break;
                }
            }
        }

        // 3) 静态资源探测（命中即停，避免过多请求）
        if (!result.isStruts2) {
            for (String res : STATIC_RESOURCES) {
                String url = target.getBaseUrl() + res;
                HttpResponseData r = http.request("GET", url, null, null,
                        target.getCookie(), target.getBasicAuthUser(), target.getBasicAuthPass());
                if (r.isConnected() && r.getStatusCode() == 200
                        && r.getBodyBytes().length > 50) {
                    result.isStruts2 = true;
                    result.detectedBy.add("static_resource:" + res);
                    break;
                }
            }
        }

        // 4) 响应头特征
        if (probe.getHeader("X-Struts-Version") != null) {
            result.isStruts2 = true;
            result.versionRange = probe.getHeader("X-Struts-Version");
            result.detectedBy.add("response_header:X-Struts-Version");
        }

        if (result.versionRange == null) {
            result.versionRange = "unknown";
        }
        return result;
    }

    /** 发送畸形 multipart 请求以触发错误页（非侵入：仅观察响应，不执行命令） */
    private HttpResponseData sendProbe(Target target) {
        // 使用安全的 OGNL 数学表达式（1+1），不执行系统命令，仅观察是否被求值
        String contentType = "%{(#a=1).(#b=1).(#a+#b)} multipart/form-data";
        return http.post(target.getFullUrl(), contentType,
                target.getCookie(), target.getBasicAuthUser(), target.getBasicAuthPass(),
                null, null);
    }

    private String inferVersion(String keyword) {
        if (keyword.contains("2.5")) return "2.5.x";
        if (keyword.contains("2.3")) return "2.3.x";
        if (keyword.contains("2.1")) return "2.1.x";
        if (keyword.contains("2.0")) return "2.0.x";
        return "unknown";
    }

    /** 指纹识别结果 */
    public static class FingerprintResult {
        public String target;
        public boolean isStruts2 = false;
        public String versionRange = "unknown";
        public final List<String> detectedBy = new ArrayList<>();

        public boolean isStruts2() { return isStruts2; }
        public String getVersionRange() { return versionRange; }
        public List<String> getDetectedBy() { return detectedBy; }
    }
}
