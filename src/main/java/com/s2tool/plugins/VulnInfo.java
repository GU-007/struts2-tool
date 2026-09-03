package com.s2tool.plugins;

/**
 * 漏洞元信息：记录漏洞库中每个漏洞的静态描述信息。
 */
public class VulnInfo {

    /** 漏洞编号，如 S2-045 */
    private String vulnId;
    /** CVE 编号，如 CVE-2017-5638 */
    private String cveId;
    /** 漏洞名称 */
    private String name;
    /** 漏洞原理简述 */
    private String description;
    /** 受影响版本范围 */
    private String affectedVersions;
    /** 注入点类型：header / parameter */
    private String injectionPoint;
    /** 适用的检测技术：math / delay / marker */
    private String[] detectionTechniques;
    /** 风险等级：high / medium / low */
    private String riskLevel;
    /** 修复建议 */
    private String fixSuggestion;

    public VulnInfo() {}

    public VulnInfo(String vulnId, String cveId, String name, String description,
                    String affectedVersions, String injectionPoint,
                    String[] detectionTechniques, String riskLevel, String fixSuggestion) {
        this.vulnId = vulnId;
        this.cveId = cveId;
        this.name = name;
        this.description = description;
        this.affectedVersions = affectedVersions;
        this.injectionPoint = injectionPoint;
        this.detectionTechniques = detectionTechniques;
        this.riskLevel = riskLevel;
        this.fixSuggestion = fixSuggestion;
    }

    public String getVulnId() { return vulnId; }
    public void setVulnId(String vulnId) { this.vulnId = vulnId; }
    public String getCveId() { return cveId; }
    public void setCveId(String cveId) { this.cveId = cveId; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public String getAffectedVersions() { return affectedVersions; }
    public void setAffectedVersions(String affectedVersions) { this.affectedVersions = affectedVersions; }
    public String getInjectionPoint() { return injectionPoint; }
    public void setInjectionPoint(String injectionPoint) { this.injectionPoint = injectionPoint; }
    public String[] getDetectionTechniques() { return detectionTechniques; }
    public void setDetectionTechniques(String[] detectionTechniques) { this.detectionTechniques = detectionTechniques; }
    public String getRiskLevel() { return riskLevel; }
    public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }
    public String getFixSuggestion() { return fixSuggestion; }
    public void setFixSuggestion(String fixSuggestion) { this.fixSuggestion = fixSuggestion; }

    /** 中文风险等级 */
    public String getRiskLevelCn() {
        if ("high".equalsIgnoreCase(riskLevel)) return "高危";
        if ("medium".equalsIgnoreCase(riskLevel)) return "中危";
        if ("low".equalsIgnoreCase(riskLevel)) return "低危";
        return riskLevel;
    }
}
