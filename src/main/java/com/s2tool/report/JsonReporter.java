package com.s2tool.report;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.s2tool.modules.Detector;
import com.s2tool.plugins.DetectionResult;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * JSON 报告生成器：结构化输出检测结果，便于二次分析。
 */
public class JsonReporter {

    private final ObjectMapper mapper = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT)
            .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);

    /**
     * 生成 JSON 报告并写入文件。
     *
     * @return 文件路径
     */
    public String writeReport(Detector.ScanReport report, Map<String, ?> vulnInfos, String outputPath) {
        Map<String, Object> root = new LinkedHashMap<>();
        Map<String, Object> scanInfo = new LinkedHashMap<>();
        scanInfo.put("target", report.target.getFullUrl());
        scanInfo.put("start_time", new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").format(new Date(report.startTime)));
        scanInfo.put("end_time", new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").format(new Date(report.endTime)));
        scanInfo.put("duration_sec", report.getDurationMs() / 1000.0);
        scanInfo.put("total_vulns", report.vulnOrder.size());
        scanInfo.put("found_vulns", report.countConfirmed());
        scanInfo.put("suspicious_vulns", report.countSuspicious());
        root.put("scan_info", scanInfo);

        if (report.fingerprint != null) {
            Map<String, Object> fp = new LinkedHashMap<>();
            fp.put("framework", report.fingerprint.isStruts2() ? "Struts2" : "unknown");
            fp.put("version_range", report.fingerprint.getVersionRange());
            fp.put("detected_by", report.fingerprint.getDetectedBy());
            root.put("fingerprint", fp);
        }

        List<Map<String, Object>> vulns = new ArrayList<>();
        for (String id : report.vulnOrder) {
            DetectionResult r = report.results.get(id);
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("vuln_id", r.getVulnId());
            v.put("status", r.getStatus().name());
            v.put("status_cn", r.getStatus().getCn());
            v.put("confidence", r.getConfidence() == null ? null : r.getConfidence().name());
            v.put("techniques", r.getTechniques());
            v.put("detail", r.getDetail());
            v.put("elapsed_ms", r.getElapsedMs());
            if (r.getRequestPreview() != null) v.put("request", r.getRequestPreview());
            if (r.getResponsePreview() != null) v.put("response_preview", r.getResponsePreview());
            if (r.getRawResponse() != null) {
                v.put("response_status_code", r.getRawResponse().getStatusCode());
            }
            if (r.getError() != null) {
                v.put("error", r.getError().getMessage());
            }
            vulns.add(v);
        }
        root.put("vulnerabilities", vulns);

        String json;
        try {
            json = mapper.writeValueAsString(root);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("JSON 序列化失败", e);
        }
        try {
            Files.write(Paths.get(outputPath), json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new IllegalStateException("写入报告文件失败: " + outputPath, e);
        }
        return outputPath;
    }
}
