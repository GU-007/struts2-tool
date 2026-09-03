package com.s2tool.plugins;

import com.s2tool.core.HttpResponseData;

import java.util.ArrayList;
import java.util.List;

/**
 * 漏洞检测结果：记录单个漏洞的检测状态、置信度、证据。
 *
 * <p>状态枚举：
 * <ul>
 *   <li>CONFIRMED   - 高置信度确认存在</li>
 *   <li>SUSPICIOUS  - 疑似存在，需人工确认</li>
 *   <li>NOT_FOUND   - 确认不存在</li>
 *   <li>ERROR       - 检测过程出错（超时/连接失败等）</li>
 *   <li>SKIPPED     - 因版本/条件不匹配跳过</li>
 * </ul></p>
 */
public class DetectionResult {

    public enum Status {
        CONFIRMED("存在"),
        SUSPICIOUS("疑似"),
        NOT_FOUND("不存在"),
        ERROR("失败"),
        SKIPPED("未检测");

        private final String cn;

        Status(String cn) {
            this.cn = cn;
        }

        public String getCn() { return cn; }
    }

    public enum Confidence {
        HIGH("高"), MEDIUM("中"), LOW("低");

        private final String cn;
        Confidence(String cn) { this.cn = cn; }
        public String getCn() { return cn; }
    }

    private final String vulnId;
    private Status status;
    private Confidence confidence;
    /** 使用的检测技术：math / delay / marker / error_keyword */
    private final List<String> techniques = new ArrayList<>();
    private String detail;
    private String requestPreview;
    private String responsePreview;
    private HttpResponseData rawResponse;
    private long elapsedMs;
    private Throwable error;

    public DetectionResult(String vulnId) {
        this.vulnId = vulnId;
        this.status = Status.NOT_FOUND;
    }

    public String getVulnId() { return vulnId; }
    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }
    public Confidence getConfidence() { return confidence; }
    public void setConfidence(Confidence confidence) { this.confidence = confidence; }
    public List<String> getTechniques() { return techniques; }
    public void addTechnique(String t) { if (!techniques.contains(t)) techniques.add(t); }
    public String getDetail() { return detail; }
    public void setDetail(String detail) { this.detail = detail; }
    public String getRequestPreview() { return requestPreview; }
    public void setRequestPreview(String requestPreview) { this.requestPreview = requestPreview; }
    public String getResponsePreview() { return responsePreview; }
    public void setResponsePreview(String responsePreview) { this.responsePreview = responsePreview; }
    public HttpResponseData getRawResponse() { return rawResponse; }
    public void setRawResponse(HttpResponseData rawResponse) { this.rawResponse = rawResponse; }
    public long getElapsedMs() { return elapsedMs; }
    public void setElapsedMs(long elapsedMs) { this.elapsedMs = elapsedMs; }
    public Throwable getError() { return error; }
    public void setError(Throwable error) { this.error = error; }

    public boolean isConfirmed() {
        return status == Status.CONFIRMED;
    }

    @Override
    public String toString() {
        return vulnId + " [" + status.getCn() + "] " + (detail == null ? "" : detail);
    }
}
