package com.s2tool.report;

import com.s2tool.modules.Detector;
import com.s2tool.plugins.DetectionResult;
import com.s2tool.plugins.VulnInfo;
import com.s2tool.utils.Logger;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;

/**
 * 控制台报告：以表格形式实时展示检测结果。
 *
 * <p>注意：所有输出符号均为 ASCII 兼容（框线除外），避免 Windows
 * GBK 控制台把 emoji 显示为乱码问号。</p>
 */
public class ConsoleReporter {

    /** 目标信息行宽 */
    private static final int WIDTH = 60;

    public void printHeader(String toolName, String version) {
        String title = " " + toolName + " v" + version + " ";
        Logger.raw("");
        Logger.raw("╔" + repeat("═", WIDTH) + "╗");
        Logger.raw("║" + center(title, WIDTH) + "║");
        Logger.raw("╚" + repeat("═", WIDTH) + "╝");
        Logger.raw("");
    }

    public void printScanStart(Detector.ScanReport report) {
        Logger.raw("目标: " + report.target.getFullUrl());
        if (report.fingerprint != null) {
            Logger.raw("指纹识别: " + (report.fingerprint.isStruts2() ? "Struts2" : "未识别到 Struts2 特征")
                    + " (版本范围: " + report.fingerprint.getVersionRange() + ")");
        }
        Logger.raw("开始时间: " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(report.startTime)));
        Logger.raw("");
    }

    public void printTable(Detector.ScanReport report, Map<String, VulnInfo> vulnInfos) {
        // 表头（不含"详情"列——完整信息在 JSON/HTML 报告中）
        Logger.raw("┌────────────┬──────────┬──────────┬──────────────┐");
        Logger.raw("│ 漏洞编号   │ 风险等级 │ 注入点   │ 状态         │");
        Logger.raw("├────────────┼──────────┼──────────┼──────────────┤");

        for (String id : report.vulnOrder) {
            DetectionResult r = report.results.get(id);
            VulnInfo info = vulnInfos.get(id);
            String risk = info != null ? info.getRiskLevelCn() : "-";
            String injection = info != null ? info.getInjectionPoint() : "-";
            String status = r.getStatus().getCn();
            Logger.raw(String.format("│ %-10s │ %-8s │ %-8s │ %-12s │",
                    id, risk, injection, status));
        }
        Logger.raw("└────────────┴──────────┴──────────┴──────────────┘");
        Logger.raw("");
    }

    public void printSummary(Detector.ScanReport report) {
        int confirmed = report.countConfirmed();
        int suspicious = report.countSuspicious();
        int errors = report.countErrors();
        int total = report.vulnOrder.size();
        Logger.raw("检测完成: 共检测 " + total + " 个漏洞，发现 " + confirmed
                + " 个存在，" + suspicious + " 个疑似" + (errors > 0 ? "，" + errors + " 个失败" : ""));
        Logger.raw("结束时间: " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(report.endTime))
                + " (耗时 " + formatDuration(report.getDurationMs()) + ")");
    }

    /** 耗时格式化：<1s 显示毫秒，否则显示秒（避免 "0s" 误导） */
    private static String formatDuration(long ms) {
        if (ms < 1000) {
            return ms + "ms";
        }
        return String.format("%.1fs", ms / 1000.0);
    }

    /**
     * 打印单个漏洞的动态检测证据（仅 -v 时调用）。
     *
     * <p>只输出本次检测产生的动态信息（使用了哪些技术、判定详情、
     * 响应状态码、耗时、异常），不含 CVE/影响版本/修复建议等静态元数据
     * ——那些固定知识对使用者无信息量，已在 JSON/HTML 报告中归档。</p>
     */
    public void printDetectionEvidence(DetectionResult r) {
        Logger.raw("");
        Logger.raw("  [" + r.getVulnId() + "] 检测证据");
        if (!r.getTechniques().isEmpty()) {
            Logger.raw("    检测技术: " + String.join(", ", r.getTechniques()));
        }
        if (r.getDetail() != null && !r.getDetail().isEmpty()) {
            Logger.raw("    判定详情: " + r.getDetail());
        }
        if (r.getRawResponse() != null) {
            Logger.raw("    响应状态码: " + r.getRawResponse().getStatusCode()
                    + "    耗时: " + r.getElapsedMs() + "ms");
        }
        if (r.getError() != null) {
            Logger.raw("    错误: " + r.getError().getMessage());
        }
    }

    private static String repeat(String s, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append(s);
        return sb.toString();
    }

    private static String center(String s, int width) {
        if (s.length() >= width) return s;
        int left = (width - s.length()) / 2;
        int right = width - s.length() - left;
        return repeat(" ", left) + s + repeat(" ", right);
    }
}
