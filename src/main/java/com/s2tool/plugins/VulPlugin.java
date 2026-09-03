package com.s2tool.plugins;

import com.s2tool.core.HttpClient;
import com.s2tool.core.Target;

/**
 * 漏洞插件接口：所有漏洞检测插件的统一契约。
 *
 * <p>新增漏洞只需实现本接口并注册到 {@link PluginManager}，
 * 无需修改核心引擎代码。核心引擎（{@link HttpClient}、payload 构造、
 * 日志等）通过 {@link PluginContext} 对插件透明可用。</p>
 */
public interface VulPlugin {

    /**
     * 返回漏洞元信息（编号、CVE、风险等级等）。
     */
    VulnInfo getInfo();

    /**
     * 执行漏洞检测。
     *
     * @param target  目标信息（含 URL、Cookie、认证）
     * @param context 插件上下文（HTTP 客户端、配置等）
     * @return 检测结果
     */
    DetectionResult check(Target target, PluginContext context);

    /**
     * 插件显示名称。
     */
    default String displayName() {
        return getInfo().getVulnId();
    }
}
