package com.s2tool.plugins;

import com.s2tool.core.HttpClient;
import com.s2tool.core.Target;

import java.util.Map;

/**
 * 插件上下文：向漏洞插件暴露核心引擎能力与检测配置。
 */
public class PluginContext {

    private final HttpClient httpClient;
    private final Target target;
    /** 额外请求头（如 JWT、Basic 等） */
    private final Map<String, String> extraHeaders;

    public PluginContext(HttpClient httpClient, Target target,
                         Map<String, String> extraHeaders) {
        this.httpClient = httpClient;
        this.target = target;
        this.extraHeaders = extraHeaders;
    }

    public HttpClient getHttpClient() { return httpClient; }
    public Target getTarget() { return target; }
    public Map<String, String> getExtraHeaders() { return extraHeaders; }
}
