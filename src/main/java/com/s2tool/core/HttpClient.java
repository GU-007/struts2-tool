package com.s2tool.core;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * 核心 HTTP 客户端：封装 Apache HttpClient，提供统一的请求发送接口。
 *
 * <p>特性：
 * <ul>
 *   <li>连接池复用</li>
 *   <li>连接/读取超时控制</li>
 *   <li>自定义请求头（含 Content-Type 注入点）</li>
 *   <li>Cookie、Basic Auth、HTTP/HTTPS 代理支持</li>
 *   <li>忽略 SSL 证书校验（渗透测试场景）</li>
 *   <li>响应时间测量（用于延时检测）</li>
 *   <li>禁止自动重定向（由上层决定是否跟随）</li>
 * </ul></p>
 */
public class HttpClient {

    private final CloseableHttpClient client;
    private final int connectTimeoutMs;
    private final int readTimeoutMs;
    private final String userAgent;

    public HttpClient(int connectTimeoutMs, int readTimeoutMs, String userAgent,
                      String proxyHost, int proxyPort, String proxyUser, String proxyPass,
                      boolean ignoreSsl) {
        this.connectTimeoutMs = connectTimeoutMs;
        this.readTimeoutMs = readTimeoutMs;
        this.userAgent = userAgent;

        RequestConfig.Builder configBuilder = RequestConfig.custom()
                .setConnectTimeout(connectTimeoutMs)
                .setSocketTimeout(readTimeoutMs)
                .setConnectionRequestTimeout(connectTimeoutMs)
                .setCookieSpec(CookieSpecs.STANDARD)
                // 关键：禁止自动重定向，让上层决定
                .setRedirectsEnabled(false)
                .setMaxRedirects(0);

        HttpClientBuilder builder = HttpClientBuilder.create();

        try {
            if (ignoreSsl) {
                SSLContext sslContext = SSLContexts.custom()
                        .loadTrustMaterial(null, (chain, authType) -> true)
                        .build();
                SSLConnectionSocketFactory sslFactory = new SSLConnectionSocketFactory(
                        sslContext, NoopHostnameVerifier.INSTANCE);
                Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
                        .register("https", sslFactory)
                        .register("http", PlainConnectionSocketFactory.getSocketFactory())
                        .build();
                PoolingHttpClientConnectionManager cm = new PoolingHttpClientConnectionManager(registry);
                cm.setMaxTotal(64);
                cm.setDefaultMaxPerRoute(16);
                builder.setConnectionManager(cm);
            }
        } catch (Exception e) {
            throw new IllegalStateException("初始化 SSL 上下文失败", e);
        }

        if (proxyHost != null && !proxyHost.isEmpty()) {
            HttpHost proxy = new HttpHost(proxyHost, proxyPort);
            builder.setProxy(proxy);
            if (proxyUser != null) {
                BasicCredentialsProvider creds = new BasicCredentialsProvider();
                creds.setCredentials(new AuthScope(proxyHost, proxyPort),
                        new UsernamePasswordCredentials(proxyUser, proxyPass));
                builder.setDefaultCredentialsProvider(creds);
            }
        }

        builder.setDefaultRequestConfig(configBuilder.build());
        // 关闭连接复用限制的 keep-alive 策略优化
        builder.setMaxConnPerRoute(16);
        builder.setMaxConnTotal(64);
        this.client = builder.build();
    }

    /**
     * 便捷构造：默认超时（连接 5s / 读取 15s）
     */
    public HttpClient() {
        this(5000, 15000, null, null, 0, null, null, true);
    }

    /**
     * 发送 HTTP 请求（POST，带 Content-Type 自定义头），用于 S2-045 注入。
     *
     * @param url          目标 URL
     * @param contentType  Content-Type 头值（可包含 OGNL payload）
     * @param cookie       会话 Cookie（可空）
     * @param basicAuthUser  Basic Auth 用户名（可空）
     * @param basicAuthPass  Basic Auth 密码（可空）
     * @param body         请求体（可空）
     * @param extraHeaders 额外请求头（可空）
     * @return 结构化响应
     */
    public HttpResponseData post(String url, String contentType, String cookie,
                                 String basicAuthUser, String basicAuthPass,
                                 byte[] body, Map<String, String> extraHeaders) {
        HttpPost post = new HttpPost(url);
        if (contentType != null) {
            post.setHeader("Content-Type", contentType);
        }
        applyCommonHeaders(post, cookie, basicAuthUser, basicAuthPass, extraHeaders);
        if (body != null && body.length > 0) {
            post.setEntity(new org.apache.http.entity.ByteArrayEntity(body));
        }
        return execute(post);
    }

    /**
     * 发送任意方法 / 头的请求。
     */
    public HttpResponseData request(String method, String url, Map<String, String> headers,
                                    byte[] body, String cookie,
                                    String basicAuthUser, String basicAuthPass) {
        RequestBuilder rb = RequestBuilder.create(method).setUri(url);
        if (headers != null) {
            for (Map.Entry<String, String> e : headers.entrySet()) {
                rb.setHeader(e.getKey(), e.getValue());
            }
        }
        applyCommonHeaders(rb, cookie, basicAuthUser, basicAuthPass, null);
        if (body != null && body.length > 0) {
            rb.setEntity(new org.apache.http.entity.ByteArrayEntity(body));
        }
        return execute(rb.build());
    }

    private void applyCommonHeaders(HttpUriRequest request, String cookie,
                                    String basicAuthUser, String basicAuthPass,
                                    Map<String, String> extraHeaders) {
        if (userAgent != null && !userAgent.isEmpty()) {
            request.setHeader("User-Agent", userAgent);
        }
        request.setHeader("Accept", "*/*");
        // 关键：要求服务器不使用 chunked 传输编码。
        // 实测 Jetty 9.2.x 的 chunked 响应与 Apache HttpClient 4.5.x 存在
        // "CRLF expected at end of chunk" 兼容性问题（S2-045 命令执行回显场景），
        // 通过 Connection: close 让服务器以 Content-Length 方式返回。
        request.setHeader("Connection", "close");
        if (cookie != null && !cookie.isEmpty()) {
            request.setHeader("Cookie", cookie);
        }
        if (basicAuthUser != null) {
            request.setHeader("Authorization", "Basic " +
                    java.util.Base64.getEncoder().encodeToString(
                            (basicAuthUser + ":" + (basicAuthPass == null ? "" : basicAuthPass))
                                    .getBytes(StandardCharsets.UTF_8)));
        }
        if (extraHeaders != null) {
            for (Map.Entry<String, String> e : extraHeaders.entrySet()) {
                request.setHeader(e.getKey(), e.getValue());
            }
        }
    }

    private void applyCommonHeaders(RequestBuilder rb, String cookie,
                                    String basicAuthUser, String basicAuthPass,
                                    Map<String, String> extraHeaders) {
        if (userAgent != null && !userAgent.isEmpty()) {
            rb.setHeader("User-Agent", userAgent);
        }
        rb.setHeader("Accept", "*/*");
        // 同 applyCommonHeaders(HttpUriRequest)：禁用 chunked 传输编码，
        // 规避 Jetty chunked 响应与 HttpClient 的兼容性问题
        rb.setHeader("Connection", "close");
        if (cookie != null && !cookie.isEmpty()) {
            rb.setHeader("Cookie", cookie);
        }
        if (basicAuthUser != null) {
            rb.setHeader("Authorization", "Basic " +
                    java.util.Base64.getEncoder().encodeToString(
                            (basicAuthUser + ":" + (basicAuthPass == null ? "" : basicAuthPass))
                                    .getBytes(StandardCharsets.UTF_8)));
        }
        if (extraHeaders != null) {
            for (Map.Entry<String, String> e : extraHeaders.entrySet()) {
                rb.setHeader(e.getKey(), e.getValue());
            }
        }
    }

    /**
     * 执行请求并测量耗时。
     */
    public HttpResponseData execute(HttpUriRequest request) {
        long start = System.currentTimeMillis();
        try (CloseableHttpResponse resp = client.execute(request)) {
            long elapsed = System.currentTimeMillis() - start;
            int status = resp.getStatusLine().getStatusCode();
            Map<String, String> respHeaders = new HashMap<>();
            for (Header h : resp.getAllHeaders()) {
                respHeaders.put(h.getName(), h.getValue());
            }
            HttpEntity entity = resp.getEntity();
            byte[] bodyBytes = entity != null ? EntityUtils.toByteArray(entity) : new byte[0];
            String bodyStr = decodeBody(bodyBytes, respHeaders);
            return new HttpResponseData(status, respHeaders, bodyStr, bodyBytes, elapsed, null);
        } catch (IOException e) {
            long elapsed = System.currentTimeMillis() - start;
            return new HttpResponseData(0, new HashMap<>(), "", new byte[0], elapsed, e);
        }
    }

    private String decodeBody(byte[] bytes, Map<String, String> headers) {
        String charsetName = "ISO-8859-1";
        String ct = headers.get("Content-Type");
        if (ct != null) {
            int idx = ct.toLowerCase().indexOf("charset=");
            if (idx >= 0) {
                charsetName = ct.substring(idx + 8).split(";")[0].trim();
            }
        }
        try {
            Charset cs = Charset.forName(charsetName);
            return new String(bytes, cs);
        } catch (Exception e) {
            return new String(bytes, StandardCharsets.ISO_8859_1);
        }
    }

    public void close() {
        try {
            client.close();
        } catch (IOException ignored) {
        }
    }

    public int getConnectTimeoutMs() {
        return connectTimeoutMs;
    }

    public int getReadTimeoutMs() {
        return readTimeoutMs;
    }
}
