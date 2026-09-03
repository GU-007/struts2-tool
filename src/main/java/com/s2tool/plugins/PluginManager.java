package com.s2tool.plugins;

import com.s2tool.plugins.impl.S2_045;
import com.s2tool.plugins.impl.S2_046;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 插件管理器：负责注册、加载和遍历漏洞插件。
 *
 * <p>当前内置 2 个检测插件：S2-045、S2-046（均为 CVE-2017-5638 家族）。
 * 架构上通过 {@link #register(VulPlugin)} 支持任意扩展。</p>
 */
public class PluginManager {

    private final Map<String, VulPlugin> plugins = new LinkedHashMap<>();

    public PluginManager() {
        registerDefaults();
    }

    private void registerDefaults() {
        register(new S2_045());
        register(new S2_046());
        // 预留扩展点：register(new S2_057());
        // 预留扩展点：register(new S2_061());
    }

    public void register(VulPlugin plugin) {
        plugins.put(plugin.getInfo().getVulnId(), plugin);
    }

    public VulPlugin get(String vulnId) {
        return plugins.get(vulnId);
    }

    public List<VulPlugin> getAll() {
        return Collections.unmodifiableList(new ArrayList<>(plugins.values()));
    }

    public int size() {
        return plugins.size();
    }
}
