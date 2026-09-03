package com.s2tool.modules;

import com.s2tool.core.HttpClient;
import com.s2tool.core.Target;
import com.s2tool.plugins.DetectionResult;
import com.s2tool.plugins.PluginContext;
import com.s2tool.plugins.PluginManager;
import com.s2tool.plugins.VulPlugin;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 检测调度器：编排指纹识别 → 插件检测 → 结果汇总的完整流程。
 *
 * <p>负责创建插件上下文、遍历漏洞插件执行 check()、收集结果。
 * 采用单检测模式（无 fast/deep 区分）。</p>
 */
public class Detector {

    private final PluginManager pluginManager;
    private final Map<String, String> extraHeaders;
    private final String proxyHost;
    private final int proxyPort;
    private final int connectTimeoutMs;
    private final int readTimeoutMs;

    private Detector(Builder b) {
        this.pluginManager = b.pluginManager;
        this.extraHeaders = b.extraHeaders;
        this.proxyHost = b.proxyHost;
        this.proxyPort = b.proxyPort;
        this.connectTimeoutMs = b.connectTimeoutMs;
        this.readTimeoutMs = b.readTimeoutMs;
    }

    /**
     * 对单个目标执行完整检测流程。
     *
     * @return 检测报告
     */
    public ScanReport scan(Target target) {
        ScanReport report = new ScanReport();
        report.target = target;
        report.startTime = System.currentTimeMillis();

        HttpClient http = new HttpClient(connectTimeoutMs, readTimeoutMs,
                target.getUserAgent(), proxyHost, proxyPort, null, null, true);

        try {
            // 第一步：指纹识别
            Fingerprinter fp = new Fingerprinter(http);
            report.fingerprint = fp.fingerprint(target);

            // 第二步：插件检测
            PluginContext ctx = new PluginContext(http, target, extraHeaders);
            for (VulPlugin plugin : pluginManager.getAll()) {
                DetectionResult r;
                try {
                    r = plugin.check(target, ctx);
                } catch (Exception e) {
                    r = new DetectionResult(plugin.getInfo().getVulnId());
                    r.setStatus(DetectionResult.Status.ERROR);
                    r.setError(e);
                    r.setDetail("检测异常: " + e.getMessage());
                }
                report.results.put(r.getVulnId(), r);
                report.vulnOrder.add(r.getVulnId());
            }
        } finally {
            http.close();
            report.endTime = System.currentTimeMillis();
        }
        return report;
    }

    /** 扫描报告：单目标检测结果汇总 */
    public static class ScanReport {
        public Target target;
        public Fingerprinter.FingerprintResult fingerprint;
        public final Map<String, DetectionResult> results = new LinkedHashMap<>();
        public final List<String> vulnOrder = new ArrayList<>();
        public long startTime;
        public long endTime;

        public long getDurationMs() {
            return endTime - startTime;
        }

        public int countConfirmed() {
            return (int) results.values().stream().filter(DetectionResult::isConfirmed).count();
        }

        public int countSuspicious() {
            return (int) results.values().stream()
                    .filter(r -> r.getStatus() == DetectionResult.Status.SUSPICIOUS).count();
        }

        public int countErrors() {
            return (int) results.values().stream()
                    .filter(r -> r.getStatus() == DetectionResult.Status.ERROR).count();
        }

        public List<DetectionResult> getConfirmed() {
            List<DetectionResult> list = new ArrayList<>();
            for (String id : vulnOrder) {
                DetectionResult r = results.get(id);
                if (r.isConfirmed()) list.add(r);
            }
            return list;
        }
    }

    /** Builder 模式构造 Detector */
    public static class Builder {
        private PluginManager pluginManager = new PluginManager();
        private Map<String, String> extraHeaders = new LinkedHashMap<>();
        private String proxyHost;
        private int proxyPort;
        private int connectTimeoutMs = 5000;
        private int readTimeoutMs = 15000;

        public Builder pluginManager(PluginManager pm) { this.pluginManager = pm; return this; }
        public Builder extraHeaders(Map<String, String> h) { this.extraHeaders = h; return this; }
        public Builder addHeader(String k, String v) { this.extraHeaders.put(k, v); return this; }
        public Builder proxy(String host, int port) { this.proxyHost = host; this.proxyPort = port; return this; }
        public Builder connectTimeoutMs(int ms) { this.connectTimeoutMs = ms; return this; }
        public Builder readTimeoutMs(int ms) { this.readTimeoutMs = ms; return this; }

        public Detector build() {
            return new Detector(this);
        }
    }
}
