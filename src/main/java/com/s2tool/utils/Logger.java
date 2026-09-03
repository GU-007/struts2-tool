package com.s2tool.utils;

import java.io.PrintStream;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * 控制台日志工具：支持分级输出、彩色标记、静默模式。
 *
 * <p>等级：ERROR > WARN > INFO > DEBUG。默认 INFO。
 * 颜色仅在支持 ANSI 的终端输出，Windows 下自动关闭（避免乱码）。</p>
 *
 * <p>输出不附加符号前缀（[+]、[!] 等），消息自身已表达语义
 * （如"执行成功"、"检测完成"、"失败"）。</p>
 */
public final class Logger {

    public enum Level { DEBUG, INFO, WARN, ERROR }

    private static Level currentLevel = Level.INFO;
    private static boolean quiet = false;
    private static boolean colorEnabled = false;
    private static final PrintStream OUT = System.out;
    private static final PrintStream ERR = System.err;

    static {
        String os = System.getProperty("os.name", "").toLowerCase();
        // Windows 10+ 支持 ANSI 但 cmd 默认不开；为稳妥默认关闭颜色
        colorEnabled = !os.contains("win") && System.console() != null;
    }

    private Logger() {}

    public static void setLevel(Level level) {
        if (level != null) currentLevel = level;
    }

    public static void setQuiet(boolean q) {
        quiet = q;
    }

    public static void setColorEnabled(boolean enabled) {
        colorEnabled = enabled;
    }

    /** 直接输出原始行（不经过级别过滤），用于表格等结构化输出 */
    public static void raw(String msg) {
        if (!quiet) OUT.println(msg);
    }

    /** DEBUG：仅在 -v 模式输出 */
    public static void debug(String msg) {
        if (currentLevel.ordinal() <= Level.DEBUG.ordinal() && !quiet) {
            OUT.println(colorize(msg, "\u001B[90m"));
        }
    }

    /** 普通信息 */
    public static void info(String msg) {
        if (currentLevel.ordinal() <= Level.INFO.ordinal() && !quiet) {
            OUT.println(colorize(msg, "\u001B[36m"));
        }
    }

    /** 成功/正向信息 */
    public static void success(String msg) {
        if (currentLevel.ordinal() <= Level.INFO.ordinal() && !quiet) {
            OUT.println(colorize(msg, "\u001B[32m"));
        }
    }

    /** 失败/负向信息 */
    public static void fail(String msg) {
        if (currentLevel.ordinal() <= Level.INFO.ordinal() && !quiet) {
            OUT.println(colorize(msg, "\u001B[31m"));
        }
    }

    /** 警告 */
    public static void warn(String msg) {
        if (currentLevel.ordinal() <= Level.WARN.ordinal() && !quiet) {
            OUT.println(colorize(msg, "\u001B[33m"));
        }
    }

    public static void error(String msg) {
        if (currentLevel.ordinal() <= Level.ERROR.ordinal() && !quiet) {
            ERR.println(colorize(msg, "\u001B[31m"));
        }
    }

    public static void error(String msg, Throwable t) {
        if (currentLevel.ordinal() <= Level.ERROR.ordinal() && !quiet) {
            ERR.println(colorize(msg, "\u001B[31m"));
            if (t != null && currentLevel == Level.DEBUG) {
                t.printStackTrace(ERR);
            }
        }
    }

    /** 带时间戳输出（用于批量扫描进度等场景） */
    public static void timed(String msg) {
        String ts = new SimpleDateFormat("HH:mm:ss").format(new Date());
        if (!quiet) OUT.println("[" + ts + "] " + msg);
    }

    private static String colorize(String text, String ansi) {
        if (!colorEnabled) return text;
        return ansi + text + "\u001B[0m";
    }
}
