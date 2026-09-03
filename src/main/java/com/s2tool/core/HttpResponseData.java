package com.s2tool.core;

import java.util.Collections;
import java.util.Map;

/**
 * 结构化 HTTP 响应：状态码、响应头、响应体、耗时、异常。
 */
public class HttpResponseData {

    private final int statusCode;
    private final Map<String, String> headers;
    private final String body;
    private final byte[] bodyBytes;
    private final long elapsedMs;
    private final Exception error;

    public HttpResponseData(int statusCode, Map<String, String> headers, String body,
                            byte[] bodyBytes, long elapsedMs, Exception error) {
        this.statusCode = statusCode;
        this.headers = headers != null ? headers : Collections.emptyMap();
        this.body = body != null ? body : "";
        this.bodyBytes = bodyBytes != null ? bodyBytes : new byte[0];
        this.elapsedMs = elapsedMs;
        this.error = error;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public String getBody() {
        return body;
    }

    public byte[] getBodyBytes() {
        return bodyBytes;
    }

    public long getElapsedMs() {
        return elapsedMs;
    }

    public Exception getError() {
        return error;
    }

    /** 连接是否成功（statusCode != 0） */
    public boolean isConnected() {
        return statusCode != 0 && error == null;
    }

    /** 获取指定响应头（忽略大小写） */
    public String getHeader(String name) {
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (e.getKey().equalsIgnoreCase(name)) {
                return e.getValue();
            }
        }
        return null;
    }

    public String getLocation() {
        return getHeader("Location");
    }
}
