package com.s2tool.core;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * 目标信息模型：封装目标 URL 解析结果、Cookie、认证等会话状态。
 *
 * <p>负责将用户输入的 URL 规范化为可用的完整地址，并拆解出
 * scheme / host / port / path 等组成部分供 HTTP 客户端使用。</p>
 */
public class Target {

    private final String rawUrl;
    private final String scheme;
    private final String host;
    private final int port;
    private final String path;
    private String cookie;
    private String basicAuthUser;
    private String basicAuthPass;
    private String userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

    public Target(String url) throws IllegalArgumentException {
        this.rawUrl = normalize(url);
        try {
            URI uri = new URI(this.rawUrl);
            this.scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase() : "http";
            this.host = uri.getHost();
            if (host == null || host.isEmpty()) {
                throw new IllegalArgumentException("URL 缺少主机名: " + url);
            }
            int p = uri.getPort();
            if (p == -1) {
                p = "https".equals(scheme) ? 443 : 80;
            }
            this.port = p;
            String pth = uri.getPath();
            this.path = (pth == null || pth.isEmpty()) ? "/" : pth;
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("URL 格式不正确: " + url, e);
        }
    }

    private String normalize(String url) {
        if (url == null || url.trim().isEmpty()) {
            throw new IllegalArgumentException("URL 不能为空");
        }
        url = url.trim();
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "http://" + url;
        }
        return url;
    }

    /** 完整的根地址（含 scheme://host:port） */
    public String getBaseUrl() {
        return scheme + "://" + host + ":" + port;
    }

    /** 完整 URL（含路径） */
    public String getFullUrl() {
        return getBaseUrl() + path;
    }

    public String getRawUrl() {
        return rawUrl;
    }

    public String getScheme() {
        return scheme;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    /** 目标路径（用户指定 URL 的路径部分），如 /upload.action 或 / */
    public String getPath() {
        return path;
    }

    /** 探测路径：若用户只给了根路径，则尝试常见 action 路径（可被注入点探测覆盖） */
    public String getProbePath() {
        return path;
    }

    public String getCookie() {
        return cookie;
    }

    public void setCookie(String cookie) {
        this.cookie = cookie;
    }

    public String getBasicAuthUser() {
        return basicAuthUser;
    }

    public String getBasicAuthPass() {
        return basicAuthPass;
    }

    public void setBasicAuth(String user, String pass) {
        this.basicAuthUser = user;
        this.basicAuthPass = pass;
    }

    public boolean hasBasicAuth() {
        return basicAuthUser != null;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        if (userAgent != null && !userAgent.trim().isEmpty()) {
            this.userAgent = userAgent;
        }
    }

    @Override
    public String toString() {
        return getFullUrl();
    }
}
