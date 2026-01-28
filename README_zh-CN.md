# IDA Pro MCP Multi

[English](README.md) | [中文](README_zh-CN.md)

> 📌 **基于**: 本项目基于 [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) 进行二次开发，扩展了多实例支持和漏洞扫描功能。

一个强大的 [MCP 服务器](https://modelcontextprotocol.io/introduction)，用于 IDA Pro 中的 AI 辅助逆向工程，支持同时分析多个二进制文件。

## 为什么开发这个项目？

原版 [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) 是一个优秀的 AI 辅助逆向工程工具，但我们在实际使用中遇到了一些限制：

### 问题 1：单实例限制

在逆向分析复杂软件时，通常需要同时分析多个相关的二进制文件：
- 主程序（`main.exe`）
- 多个 DLL/共享库（`helper.dll`、`crypto.dll` 等）
- 第三方库

原项目一次只支持**一个 IDA 实例**，使得跨二进制分析变得繁琐且低效。

### 问题 2：缺少内置漏洞检测

安全研究人员需要快速识别潜在的危险代码模式。手动搜索漏洞函数调用非常耗时。

## 新增功能

### 🔗 多实例支持

通过 Gateway 架构同时分析多个二进制文件：

```
AI 客户端 ──MCP──> 网关 (端口 13337) ──> IDA 实例 1 (main.exe, 端口 13338)
                                     ──> IDA 实例 2 (helper.dll, 端口 13339)
                                     ──> IDA 实例 3 (crypto.dll, 端口 13340)
```

**工作原理：**

1. 第一个 IDA 实例自动启动 **Gateway 服务器**（端口 13337）
2. 后续每个 IDA 实例向 Gateway 注册并获得唯一端口
3. AI 客户端连接到 Gateway，Gateway 将请求路由到相应的实例

**实例管理工具：**

| 工具 | 描述 |
|------|------|
| `list_instances()` | 列出所有注册的 IDA 实例 |
| `switch_instance(target)` | 切换默认目标实例（通过 ID 或二进制文件名） |
| `get_current_instance()` | 获取当前默认实例的信息 |
| `check_instance_health(target)` | 检查实例是否响应 |

**指定特定实例：**

大多数工具接受可选的 `target` 参数：

```json
{
  "method": "decompile",
  "params": {
    "addr": "0x401000",
    "target": "helper.dll"
  }
}
```

**传统模式：**

禁用多实例支持：
```sh
IDA_MCP_LEGACY=1
```

### 🔍 漏洞扫描

AI 辅助漏洞扫描，识别潜在危险的函数调用：

**工具：**

| 工具 | 描述 |
|------|------|
| `vuln_scan(output_dir, categories, min_risk)` | 扫描二进制文件漏洞，返回摘要 |
| `vuln_scan_details(category, limit, offset, risk_level)` | 获取特定类别的详细发现 |
| `vuln_scan_function(addr)` | 扫描特定函数的漏洞模式 |
| `vuln_categories()` | 列出所有漏洞类别和相关函数 |

**支持的漏洞类别：**

| 类别 | 危险函数 | 描述 |
|------|----------|------|
| **格式化字符串** | printf, sprintf, fprintf 等 | 非常量格式字符串 |
| **缓冲区溢出** | strcpy, memcpy, gets 等 | 无边界复制、可控大小 |
| **命令注入** | system, popen, exec* 等 | 非常量命令 |
| **整数溢出** | malloc, calloc, realloc | 可能溢出的大小 |
| **释放后使用** | free() | 潜在的 UAF/双重释放 |
| **路径遍历** | fopen, open 等 | 可控路径 |
| **SQL 注入** | sqlite3_exec, mysql_query | 非常量 SQL |

**工作流程：**

1. 让 AI "扫描漏洞" 或 "scan for vulnerabilities"
2. AI 调用 `vuln_scan()` 获取按类别的摘要
3. 查看摘要并选择要深入分析的类别
4. AI 使用 `vuln_scan_details(category)` 和 `decompile()` 分析特定发现

**注意：** 详细结果保存到 `.ida-mcp-vuln/` 文件夹以最小化 token 使用。

## 前置要求

- [IDA Pro](https://hex-rays.com/ida-pro)（8.3 或更高版本，推荐 9）
- 任何 MCP 兼容客户端（Claude、Cursor、VS Code、Roo Code 等）

## 安装

### 步骤 1：设置环境变量

将 IDA 的 Python `site-packages` 目录添加到环境变量：

**Windows:**
```
D:\你的路径\ida\python311\Lib\site-packages
```

将此路径添加到系统的 `PYTHONPATH` 环境变量中。

### 步骤 2：安装 MCP 包

在 IDA 的 Python 目录中打开终端并运行：

```bash
# 进入 IDA 的 Python 目录
cd "D:\你的路径\ida\python311"

# 安装 MCP 包
python.exe -m pip install --upgrade git+https://github.com/QYmag1c/ida-pro-mcp-multi
```

### 步骤 3：安装 IDA 插件并配置 MCP 客户端

```bash
# 安装 IDA 插件并配置 MCP 客户端
"D:\你的路径\ida\python311\Scripts\ida-pro-mcp.exe" --install

# （可选）查看 MCP 配置以进行手动设置
"D:\你的路径\ida\python311\Scripts\ida-pro-mcp.exe" --config
```

**注意：** 将 `D:\你的路径\ida` 替换为你实际的 IDA Pro 安装路径。

### 步骤 4：重启

**重要**：完全重启 IDA Pro 和你的 MCP 客户端以使安装生效。

### 验证安装

1. 打开 IDA Pro 并加载一个二进制文件
2. 进入 **Edit → Plugins → MCP**（或按 `Ctrl+Alt+M`）
3. 你应该在输出窗口中看到 `[MCP] Server started`

## 架构

```
src/ida_pro_mcp/
├── server.py              # MCP 服务器 + 实例管理工具
├── gateway.py             # Gateway 服务器，用于多实例路由
├── ida_mcp.py             # IDA 插件加载器（向 Gateway 注册）
└── ida_mcp/
    ├── api_core.py        # 核心函数（decompile, disasm 等）
    ├── api_analysis.py    # 分析操作
    ├── api_vuln.py        # 漏洞扫描（新增）
    ├── api_memory.py      # 内存操作
    ├── api_types.py       # 类型操作
    ├── api_modify.py      # 修改操作
    ├── api_stack.py       # 栈帧操作
    ├── api_debug.py       # 调试器操作
    └── ...
```

## 所有可用工具

本项目包含原项目的所有工具，以及新增的多实例和漏洞扫描功能。

### 实例管理（新增）
- `list_instances()`, `switch_instance()`, `get_current_instance()`, `check_instance_health()`

### 漏洞扫描（新增）
- `vuln_scan()`, `vuln_scan_details()`, `vuln_scan_function()`, `vuln_categories()`

### 核心函数
- `lookup_funcs()`, `int_convert()`, `list_funcs()`, `list_globals()`, `imports()`, `decompile()`, `disasm()`, `xrefs_to()`, `callees()`

### 修改操作
- `set_comments()`, `patch_asm()`, `declare_type()`, `rename()`

### 内存操作
- `get_bytes()`, `get_int()`, `get_string()`, `get_global_value()`, `patch()`, `put_int()`

### 分析操作
- `py_eval()`, `analyze_funcs()`, `find_regex()`, `find_bytes()`, `find_insns()`, `find()`, `basic_blocks()`, `callgraph()`

### 类型操作
- `set_type()`, `infer_types()`, `read_struct()`, `search_structs()`

### 栈操作
- `stack_frame()`, `declare_stack()`, `delete_stack()`

### 调试器操作（需要 `--unsafe` 标志）
- `dbg_start()`, `dbg_exit()`, `dbg_continue()`, `dbg_step_into()`, `dbg_step_over()` 等

## 致谢

- 原项目：[mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)

## 许可证

MIT 许可证 - 详见 [LICENSE](LICENSE)
