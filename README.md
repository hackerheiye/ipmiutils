# IPMIUtils - 使用文档

## 1. 概述

**IPMIUtils**是一个专业增强版的IPMI命令解析与编码工具，旨在简化和增强对服务器IPMI功能的管理。该工具提供了友好的命令行界面，支持IPMI命令的编码和解码，并可以直接执行生成的命令。

### 主要功能特性

- 安全加固：启用严格的变量检查和错误处理机制
- 错误处理增强：标准化的错误码和日志系统
- 性能优化：优化的字符串处理和命令执行逻辑
- 功能扩展：支持全量IPMI命令类型，特别是完整的传感器类型支持
- 双模式支持：同时支持命令编码和解码功能
- 实时执行：可直接执行生成的IPMI命令

## 2. 安装与设置

### 2.1 前置依赖

- **Bash**：需要Bash shell环境
- **ipmitool**：用于执行生成的IPMI命令
- **xxd**（可选）：用于高级的十六进制转换（如未安装，将使用内置实现）

### 2.2 安装步骤

```bash
# 1. 下载脚本
curl -O https://example.com/ipmiutils.sh

# 2. 设置执行权限
chmod +x ipmiutils.sh

# 3. 测试脚本
./ipmiutils.sh --help
```

## 3. 使用方法

### 3.1 基本语法

```bash
# 编码模式
./ipmiutils.sh encode <命令类型> [参数...]

# 解码模式
./ipmiutils.sh decode <十六进制字符串>
```

### 3.2 全局选项

- `--execute, -x`：直接执行生成的命令
- `--debug`：启用调试模式，显示详细日志
- `--help, -h`：显示帮助信息

## 4. 命令参考

### 4.1 用户管理命令

| 命令 | 参数 | 说明 |
|------|------|------|
| `user_set_name` | `<用户ID> <用户名>` | 设置用户名称 |
| `user_priv` | `<用户ID> <权限级别> [通道]` | 设置用户权限 |
| `user_set_password` | `<用户ID> <密码>` | 设置用户密码 |
| `user_enable` | `<用户ID>` | 启用用户 |
| `user_disable` | `<用户ID>` | 禁用用户 |

#### 4.1.1 权限级别说明

- `callback`：回调权限
- `user`：普通用户权限
- `operator`：操作员权限
- `admin`：管理员权限
- `oem`：原始设备制造商权限
- `no_access`：无访问权限

### 4.2 电源控制命令

| 命令 | 参数 | 说明 |
|------|------|------|
| `power_on` | `[延时]` | 开机（可选指定延时秒数） |
| `power_off` | `[延时]` | 关机（强制，可选指定延时秒数） |
| `power_reset` | `[延时]` | 重置（可选指定延时秒数） |
| `power_status` | 无 | 获取电源状态 |

### 4.3 传感器命令

| 命令 | 参数 | 说明 |
|------|------|------|
| `sensor_list` | 无 | 列出所有传感器 |
| `sensor_read` | `<传感器ID>` | 读取指定传感器值 |
| `sensor_set_thresh` | `<传感器ID> <阈值类型> <值>` | 设置传感器阈值 |
| `sensor_type_list` | 无 | 显示所有支持的传感器类型 |
| `sensor_by_type` | `<类型名称>` | 按类型查询传感器 |

#### 4.3.1 传感器类型列表

| 类型名称 | 十六进制代码 | 描述 |
|---------|------------|------|
| `temperature` | `0x01` | 温度传感器 |
| `voltage` | `0x02` | 电压传感器 |
| `current` | `0x03` | 电流传感器 |
| `fan` | `0x04` | 风扇传感器 |
| `physical_security` | `0x05` | 物理安全传感器 |
| `platform_security` | `0x06` | 平台安全传感器 |
| `processor` | `0x07` | 处理器传感器 |
| `power_supply` | `0x08` | 电源供应传感器 |
| `power_unit` | `0x09` | 电源单元传感器 |
| `cooling_device` | `0x0a` | 冷却设备传感器 |
| `other` | `0x0b` | 其他类型传感器 |
| `memory` | `0x0c` | 内存传感器 |
| `drive_slot` | `0x0d` | 驱动器插槽传感器 |
| `post_memory_resize` | `0x0e` | POST内存调整传感器 |
| `system_firmwares` | `0x0f` | 系统固件传感器 |
| `event_logging_disabled` | `0x10` | 事件日志禁用传感器 |
| `watchdog1` | `0x11` | 看门狗1传感器 |
| `system_event` | `0x12` | 系统事件传感器 |
| `critical_interrupt` | `0x13` | 严重中断传感器 |
| `button` | `0x14` | 按钮传感器 |
| `module_board` | `0x15` | 模块/板传感器 |
| `microcontroller` | `0x16` | 微控制器传感器 |
| `add_in_card` | `0x17` | 附加卡传感器 |
| `chassis` | `0x18` | 机箱传感器 |
| `chip_set` | `0x19` | 芯片组传感器 |
| `other_fru` | `0x1a` | 其他FRU传感器 |
| `cable_interconnect` | `0x1b` | 线缆/互连传感器 |
| `terminator` | `0x1c` | 终结器传感器 |
| `system_boot_initiated` | `0x1d` | 系统启动开始传感器 |
| `boot_error` | `0x1e` | 启动错误传感器 |
| `os_boot` | `0x1f` | 操作系统启动传感器 |
| `os_critical_stop` | `0x20` | 操作系统严重停止传感器 |
| `slot_connector` | `0x21` | 插槽/连接器传感器 |
| `system_acpi_power_state` | `0x22` | 系统ACPI电源状态传感器 |
| `watchdog2` | `0x23` | 看门狗2传感器 |
| `platform_alert` | `0x24` | 平台警报传感器 |
| `entity_presence` | `0x25` | 实体存在传感器 |
| `monitor_asic` | `0x26` | 监控ASIC传感器 |
| `lan` | `0x27` | 网络传感器 |
| `management_subsys_health` | `0x28` | 管理子系统健康传感器 |
| `battery` | `0x29` | 电池传感器 |
| `session_audit` | `0x2a` | 会话审计传感器 |
| `version_change` | `0x2b` | 版本变更传感器 |
| `fru_state` | `0x2c` | FRU状态传感器 |

#### 4.3.2 阈值类型

- `lnc` / `lower_non_critical`：下限非关键阈值
- `lc` / `lower_critical`：下限关键阈值
- `lnr` / `lower_non_recoverable`：下限不可恢复阈值
- `unc` / `upper_non_critical`：上限非关键阈值
- `uc` / `upper_critical`：上限关键阈值
- `unr` / `upper_non_recoverable`：上限不可恢复阈值

### 4.4 SEL日志命令

| 命令 | 参数 | 说明 |
|------|------|------|
| `sel_list` | 无 | 列出系统事件日志 |
| `sel_clear` | 无 | 清除系统事件日志 |
| `sel_add` | `<事件数据>` | 添加SEL事件 |

### 4.5 FRU信息命令

| 命令 | 参数 | 说明 |
|------|------|------|
| `fru_print` | 无 | 显示FRU信息 |
| `fru_read` | `<设备ID>` | 读取指定FRU设备信息 |

### 4.6 网络配置命令

| 命令 | 参数 | 说明 |
|------|------|------|
| `lan_print` | `[通道]` | 显示网络配置（默认通道1） |
| `lan_set_ip` | `<通道> <IP地址>` | 设置IP地址 |
| `lan_set_netmask` | `<通道> <子网掩码>` | 设置子网掩码 |
| `lan_set_gateway` | `<通道> <网关地址>` | 设置网关地址 |

## 5. 使用示例

### 5.1 用户管理示例

```bash
# 设置用户名称
./ipmiutils.sh encode user_set_name 3 admin

# 设置用户权限
./ipmiutils.sh encode user_priv 4 admin 1

# 设置用户密码
./ipmiutils.sh encode user_set_password 2 password123

# 启用用户
./ipmiutils.sh encode user_enable 5

# 禁用用户
./ipmiutils.sh encode user_disable 6
```

### 5.2 电源控制示例

```bash
# 检查电源状态
./ipmiutils.sh encode power_status

# 开机
./ipmiutils.sh encode power_on

# 延时30秒关机
./ipmiutils.sh encode power_off 30

# 重置服务器
./ipmiutils.sh encode power_reset
```

### 5.3 传感器命令示例

```bash
# 列出所有传感器
./ipmiutils.sh encode sensor_list

# 显示所有传感器类型
./ipmiutils.sh encode sensor_type_list

# 查询所有温度传感器
./ipmiutils.sh encode sensor_by_type temperature

# 读取传感器ID为5的值
./ipmiutils.sh encode sensor_read 5

# 设置传感器阈值（例如：设置温度传感器上限非关键阈值为85度）
./ipmiutils.sh encode sensor_set_thresh 1 upper_non_critical 85
```

### 5.4 SEL和FRU示例

```bash
# 列出SEL日志
./ipmiutils.sh encode sel_list

# 清除SEL日志
./ipmiutils.sh encode sel_clear

# 显示FRU信息
./ipmiutils.sh encode fru_print
```

### 5.5 网络配置示例

```bash
# 查看通道1的网络配置
./ipmiutils.sh encode lan_print 1

# 设置IP地址
./ipmiutils.sh encode lan_set_ip 1 192.168.1.100

# 设置子网掩码
./ipmiutils.sh encode lan_set_netmask 1 255.255.255.0

# 设置网关
./ipmiutils.sh encode lan_set_gateway 1 192.168.1.1
```

### 5.6 解码示例

```bash
# 解码IPMI命令
./ipmiutils.sh decode "06 44 04 04 01"

# 启用调试模式解码
./ipmiutils.sh decode "06 44 04 04 01" --debug
```

### 5.7 直接执行示例

```bash
# 生成并直接执行命令（查询电源状态）
./ipmiutils.sh encode power_status --execute
```

## 6. 错误代码说明

| 错误代码 | 含义 |
|---------|------|
| 1 | 无效参数 |
| 2 | 未知命令 |
| 3 | 依赖缺失 |
| 4 | 执行错误 |
| 5 | 参数范围错误 |

## 7. 注意事项与最佳实践

### 7.1 安全注意事项

- 设置用户密码时，请确保密码强度符合安全要求
- 避免在公共环境中执行可能显示敏感信息的命令
- 对于生产环境，建议在执行前先不使用`--execute`选项预览命令

### 7.2 性能优化

- 对于批量操作，建议使用脚本自动化
- 频繁使用的命令可以创建别名

### 7.3 故障排除

- 如果遇到命令执行失败，尝试使用`--debug`选项获取详细日志
- 确认IPMI服务正常运行
- 检查网络连接和防火墙设置（对于远程管理）

## 8. 兼容性

该脚本设计用于Linux系统，但也可以在支持Bash的其他操作系统（如macOS）上运行。在Windows上，可以通过WSL（Windows Subsystem for Linux）或Git Bash使用。

## 9. 版本历史

### v1.0.0
- 初始版本发布
- 支持基本的用户管理、电源控制、传感器和日志功能

### v1.1.0
- 新增完整传感器类型支持
- 增强错误处理和日志功能

### v1.2.0
- 修复电源控制命令参数传递问题
- 增强十六进制格式处理，支持大小写不敏感匹配
- 优化命令参数验证逻辑
- 全面测试并确保所有命令正常工作

## 10. 许可证

MIT License

## 11. 联系与支持

如有问题或建议，请联系开发团队。
