package com.s2tool.report;

import com.s2tool.modules.Detector;
import com.s2tool.plugins.DetectionResult;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * HTML 报告生成器：纯静态页面（内联 CSS + JS），浏览器直接打开。
 */
public class HtmlReporter {

    public String writeReport(Detector.ScanReport report, String outputPath) {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"UTF-8\">\n");
        html.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html.append("<title>Struts2 漏洞检测报告 - ").append(escapeHtml(report.target.getHost())).append("</title>\n");
        html.append("<style>\n").append(CSS).append("</style>\n");
        html.append("</head>\n<body>\n");

        // 头部
        html.append("<div class=\"header\">\n");
        html.append("<h1>Struts2 漏洞检测报告</h1>\n");
        html.append("<p>目标: <code>").append(escapeHtml(report.target.getFullUrl())).append("</code></p>\n");
        html.append("</div>\n");

        // 统计卡片
        int confirmed = report.countConfirmed();
        int suspicious = report.countSuspicious();
        html.append("<div class=\"cards\">\n");
        card(html, "检测漏洞数", String.valueOf(report.vulnOrder.size()), "blue");
        card(html, "发现漏洞", String.valueOf(confirmed), "red");
        card(html, "疑似漏洞", String.valueOf(suspicious), "orange");
        card(html, "耗时", formatDuration(report.getDurationMs()), "green");
        html.append("</div>\n");

        // 指纹信息
        if (report.fingerprint != null) {
            html.append("<div class=\"section\">\n<h2>指纹识别</h2>\n");
            html.append("<p>框架: <b>").append(report.fingerprint.isStruts2() ? "Struts2" : "未知")
                    .append("</b> | 版本范围: <b>").append(escapeHtml(report.fingerprint.getVersionRange()))
                    .append("</b></p>\n");
            html.append("<p>识别依据: ").append(escapeHtml(String.join(", ", report.fingerprint.getDetectedBy()))).append("</p>\n");
            html.append("</div>\n");
        }

        // 漏洞详情卡片
        html.append("<div class=\"section\">\n<h2>漏洞详情</h2>\n");
        for (String id : report.vulnOrder) {
            DetectionResult r = report.results.get(id);
            html.append("<details class=\"vuln-card ").append(statusClass(r)).append("\">\n");
            html.append("<summary>")
                    .append(r.getVulnId())
                    .append(" - <span class=\"status\">").append(r.getStatus().getCn()).append("</span>")
                    .append(confidenceHtml(r))
                    .append("</summary>\n");
            html.append("<div class=\"vuln-body\">\n");
            html.append("<p><b>状态:</b> ").append(r.getStatus().getCn())
                    .append(" | <b>置信度:</b> ").append(r.getConfidence() == null ? "-" : r.getConfidence().getCn())
                    .append(" | <b>检测技术:</b> ").append(escapeHtml(String.join(", ", r.getTechniques())))
                    .append(" | <b>耗时:</b> ").append(r.getElapsedMs()).append("ms</p>\n");
            html.append("<p><b>详情:</b> ").append(escapeHtml(r.getDetail() == null ? "" : r.getDetail())).append("</p>\n");
            if (r.getRequestPreview() != null) {
                html.append("<details class=\"inner\"><summary>请求</summary>\n<pre>")
                        .append(escapeHtml(r.getRequestPreview())).append("</pre></details>\n");
            }
            if (r.getResponsePreview() != null) {
                html.append("<details class=\"inner\"><summary>响应预览</summary>\n<pre>")
                        .append(escapeHtml(r.getResponsePreview())).append("</pre></details>\n");
            }
            if (r.getRawResponse() != null) {
                html.append("<p><b>响应状态码:</b> ").append(r.getRawResponse().getStatusCode()).append("</p>\n");
            }
            if (r.getError() != null) {
                html.append("<p class=\"err\"><b>错误:</b> ").append(escapeHtml(r.getError().getMessage())).append("</p>\n");
            }
            html.append("</div>\n</details>\n");
        }
        html.append("</div>\n");

        // 页脚
        html.append("<div class=\"footer\">");
        html.append("生成时间: ").append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(report.endTime)));
        html.append("</div>\n");

        html.append("</body>\n</html>\n");

        try {
            Files.write(Paths.get(outputPath), html.toString().getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new IllegalStateException("写入 HTML 报告失败: " + outputPath, e);
        }
        return outputPath;
    }

    private void card(StringBuilder html, String label, String value, String color) {
        html.append("<div class=\"card ").append(color).append("\">\n")
                .append("<div class=\"value\">").append(value).append("</div>\n")
                .append("<div class=\"label\">").append(label).append("</div>\n")
                .append("</div>\n");
    }

    private String statusClass(DetectionResult r) {
        switch (r.getStatus()) {
            case CONFIRMED: return "st-confirmed";
            case SUSPICIOUS: return "st-suspicious";
            case ERROR: return "st-error";
            default: return "st-clean";
        }
    }

    /**
     * 格式化耗时：<1s 显示毫秒（如 "352ms"），否则显示秒（如 "1.2s"）。
     * 避免毫秒级扫描被整除成 "0s" 造成误解。
     */
    private static String formatDuration(long ms) {
        if (ms < 1000) {
            return ms + "ms";
        }
        return String.format("%.1fs", ms / 1000.0);
    }

    private String confidenceHtml(DetectionResult r) {
        if (r.getConfidence() == null) return "";
        return " <span class=\"conf\">置信度:" + r.getConfidence().getCn() + "</span>";
    }

    private static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;");
    }

    private static final String CSS = ""
            + "body{font-family:'Segoe UI',Microsoft YaHei,sans-serif;margin:0;background:#f5f7fa;color:#333}"
            + ".header{background:#2c3e50;color:#fff;padding:24px 32px}"
            + ".header h1{margin:0 0 8px;font-size:24px}"
            + ".header p{margin:4px 0;color:#bdc3c7}"
            + ".header code{background:#1a252f;padding:2px 8px;border-radius:4px}"
            + ".cards{display:flex;gap:16px;padding:24px 32px;flex-wrap:wrap}"
            + ".card{flex:1;min-width:140px;background:#fff;border-radius:8px;padding:16px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.1)}"
            + ".card .value{font-size:32px;font-weight:bold}"
            + ".card .label{color:#7f8c8d;margin-top:4px}"
            + ".card.red .value{color:#e74c3c}.card.blue .value{color:#3498db}"
            + ".card.orange .value{color:#f39c12}.card.green .value{color:#27ae60}"
            + ".section{padding:0 32px 24px}"
            + ".section h2{border-bottom:2px solid #ecf0f1;padding-bottom:8px;color:#2c3e50}"
            + "details.vuln-card{background:#fff;border-radius:8px;margin:10px 0;box-shadow:0 1px 3px rgba(0,0,0,.1);overflow:hidden}"
            + "details.vuln-card summary{cursor:pointer;padding:14px 20px;font-weight:bold;border-left:4px solid #95a5a6}"
            + ".st-confirmed summary{border-left-color:#e74c3c}"
            + ".st-suspicious summary{border-left-color:#f39c12}"
            + ".st-error summary{border-left-color:#9b59b6}"
            + ".st-clean summary{border-left-color:#27ae60}"
            + ".status{font-weight:normal;font-size:13px;padding:2px 8px;border-radius:10px;background:#ecf0f1}"
            + ".st-confirmed .status{background:#fdecea;color:#e74c3c}"
            + ".st-suspicious .status{background:#fef5e7;color:#f39c12}"
            + ".conf{font-weight:normal;font-size:12px;color:#7f8c8d;margin-left:8px}"
            + ".vuln-body{padding:0 20px 16px}"
            + "details.inner{margin:8px 0}"
            + "details.inner summary{color:#3498db;cursor:pointer;font-size:13px}"
            + "pre{background:#2d3436;color:#dfe6e9;padding:12px;border-radius:6px;overflow-x:auto;font-size:12px;white-space:pre-wrap;word-break:break-all}"
            + ".err{color:#e74c3c}"
            + ".footer{padding:16px 32px;color:#95a5a6;border-top:1px solid #ecf0f1;font-size:13px}";
}
