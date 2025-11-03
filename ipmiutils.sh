#!/bin/bash

# IPMIUtils - IPMI命令处理工具
# 安全加固 | 错误处理增强 | 性能优化 | 功能扩展

# 脚本配置
set -o nounset  # 禁止使用未初始化的变量
set -o pipefail # 管道中的任何命令失败都会导致整个管道失败

# 错误代码定义
readonly ERROR_INVALID_PARAMS=1
readonly ERROR_UNKNOWN_COMMAND=2
readonly ERROR_DEPENDENCY=3
readonly ERROR_EXECUTION=4
readonly ERROR_RANGE=5

# 颜色定义
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly NC='\033[0m'

# 日志级别
readonly LOG_DEBUG=0
readonly LOG_INFO=1
readonly LOG_WARN=2
readonly LOG_ERROR=3
readonly LOG_LEVEL=${LOG_LEVEL:-$LOG_INFO}

# 兼容性 echo 函数
cecho() {
    local color=$1
    shift
    if [ "$(echo -e test)" = "test" ]; then
        # 不支持 -e 的系统
        case $color in
            "$RED") echo "$@" ;;
            "$GREEN") echo "$@" ;;
            "$YELLOW") echo "$@" ;;
            "$BLUE") echo "$@" ;;
            "$PURPLE") echo "$@" ;;
            *) echo "$@" ;;
        esac
    else
        echo -e "${color}$*${NC}"
    fi
}

# 日志函数
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    if [ $level -ge $LOG_LEVEL ]; then
        case $level in
            $LOG_DEBUG) cecho "$BLUE" "[DEBUG] $timestamp: $message" ;;
            $LOG_INFO) cecho "$GREEN" "[INFO] $timestamp: $message" ;;
            $LOG_WARN) cecho "$YELLOW" "[WARN] $timestamp: $message" ;;
            $LOG_ERROR) cecho "$RED" "[ERROR] $timestamp: $message" ;;
        esac
    fi
}

# 显示用法
usage() {
    cecho "$GREEN" "IPMIUtils - IPMI命令处理工具"
    echo ""
    cecho "$YELLOW" "编码模式:"
    echo "  $0 encode <命令类型> [参数...]"
    echo ""
    cecho "$YELLOW" "解码模式:"
    echo "  $0 decode <十六进制字符串>"
    echo ""
    cecho "$YELLOW" "全局选项:"
    echo "  --execute, -x     直接执行生成的命令"
    echo "  --debug           启用调试模式"
    echo "  --help, -h        显示帮助信息"
    echo ""
    cecho "$YELLOW" "用户管理命令:"
    echo "  user_set_name     <用户ID> <用户名>"
    echo "  user_priv         <用户ID> <权限级别> [通道]"
    echo "  user_set_password <用户ID> <密码>"
    echo "  user_enable       <用户ID>"
    echo "  user_disable      <用户ID>"
    echo ""
    cecho "$YELLOW" "电源控制命令:"
    echo "  power_on          [延时]"
    echo "  power_off         [延时]"
    echo "  power_reset       [延时]"
    echo "  power_status"
    echo ""
    cecho "$YELLOW" "传感器命令:"
    echo "  sensor_list"
    echo "  sensor_read       <传感器ID>"
    echo "  sensor_set_thresh <传感器ID> <阈值类型> <值>"
    echo "  sensor_type_list           # 显示所有传感器类型"
    echo "  sensor_by_type    <类型名称> # 按类型查询传感器"
    echo ""
    cecho "$YELLOW" "SEL日志命令:"
    echo "  sel_list"
    echo "  sel_clear"
    echo "  sel_add           <事件数据>"
    echo ""
    cecho "$YELLOW" "FRU信息命令:"
    echo "  fru_print"
    echo "  fru_read          <设备ID>"
    echo ""
    cecho "$YELLOW" "网络配置命令:"
    echo "  lan_print         [通道]"
    echo "  lan_set_ip        <通道> <IP地址>"
    echo "  lan_set_netmask   <通道> <子网掩码>"
    echo "  lan_set_gateway   <通道> <网关地址>"
    echo ""
    cecho "$YELLOW" "权限级别:"
    echo "  callback, user, operator, admin, oem, no_access"
    echo ""
    cecho "$YELLOW" "阈值类型:"
    echo "  lnc/lower_non_critical, lc/lower_critical, lnr/lower_non_recoverable"
    echo "  unc/upper_non_critical, uc/upper_critical, unr/upper_non_recoverable"
    echo ""
    cecho "$YELLOW" "示例:"
    echo "  $0 encode user_set_name 3 admin"
    echo "  $0 encode power_status"
    echo "  $0 encode sensor_list"
    echo "  $0 encode sensor_type_list      # 显示所有传感器类型"
    echo "  $0 encode sensor_by_type temperature  # 查询温度传感器"
    echo "  $0 decode \"06 44 04 04 01\" --debug"
    echo "  $0 encode user_priv 4 admin 1 --execute"
}

# 验证数字范围
validate_number_range() {
    local num=$1
    local min=$2
    local max=$3
    local param_name=$4
    
    if ! [[ "$num" =~ ^[0-9]+$ ]]; then
        log $LOG_ERROR "参数 '$param_name' 必须是数字"
        return $ERROR_INVALID_PARAMS
    fi
    
    if [ "$num" -lt "$min" ] || [ "$num" -gt "$max" ]; then
        log $LOG_ERROR "参数 '$param_name' 必须在 $min-$max 范围内"
        return $ERROR_RANGE
    fi
    
    return 0
}

# 验证十六进制格式
validate_hex_format() {
    local hex_str=$1
    local allow_prefix=${2:-true}
    
    if [ "$allow_prefix" = true ]; then
        # 允许带0x前缀
        if ! [[ "$hex_str" =~ ^0x[0-9a-fA-F]+$ ]]; then
            log $LOG_ERROR "无效的十六进制格式: $hex_str"
            return $ERROR_INVALID_PARAMS
        fi
    else
        # 不允许带前缀
        if ! [[ "$hex_str" =~ ^[0-9a-fA-F]+$ ]]; then
            log $LOG_ERROR "无效的十六进制格式: $hex_str"
            return $ERROR_INVALID_PARAMS
        fi
    fi
    
    return 0
}

# 字符串转十六进制（优化版）
string_to_hex() {
    local str="$1"
    local max_length="${2:-0}"
    local hex_result=""
    
    # 检查是否有正常的xxd命令
    if command -v xxd &> /dev/null; then
        log $LOG_DEBUG "使用系统xxd进行字符串转十六进制"
        hex_result=$(echo -n "$str" | xxd -p -c 256 | sed 's/\(..\)/0x\1 /g')
    else
        log $LOG_DEBUG "使用纯bash实现进行字符串转十六进制"
        # 使用纯bash实现的优化方法
        # 对于多字节字符和特殊字符更健壮
        local i=0
        local len=${#str}
        
        while [ $i -lt $len ]; do
            # 使用printf进行字符到十六进制的转换
            # 使用'$char'语法获取字符的ASCII值
            local char="${str:$i:1}"
            local hex=$(printf "%02x" "'$char")
            hex_result="${hex_result}0x$hex "
            i=$((i+1))
        done
    fi
    
    # 处理填充
    if [ $max_length -gt 0 ]; then
        local current_chars=${#str}
        local padding_needed=$((max_length - current_chars))
        
        if [ $padding_needed -gt 0 ]; then
            # 优化填充逻辑，避免不必要的循环
            local padding=$(printf "0x00 %.0s" $(seq 1 $padding_needed))
            hex_result="${hex_result}${padding}"
        fi
    fi
    
    # 移除末尾空格并返回
    echo "$hex_result" | sed 's/[[:space:]]*$//'
}

# 十进制转十六进制
dec_to_hex() {
    local dec=$1
    printf "0x%02x" $dec
}

# 编码：设置用户名（增强版）
encode_user_set_name() {
    local user_id=$1
    local username=$2
    
    # 验证用户ID范围
    validate_number_range "$user_id" 1 255 "用户ID" || return $ERROR_RANGE
    
    # 验证用户名长度（IPMI通常限制为16字符）
    if [ ${#username} -gt 16 ]; then
        log $LOG_WARN "用户名过长，将被截断为16个字符"
        username="${username:0:16}"
    fi
    
    local user_id_hex=$(dec_to_hex $user_id)
    
    cecho "$YELLOW" "=== 编码: 设置用户名 ==="
    cecho "$GREEN" "用户ID: $user_id ($user_id_hex)"
    cecho "$GREEN" "用户名: $username"
    
    # 使用优化的字符串转十六进制函数
    local hex_username=$(string_to_hex "$username" 16)
    local command="0x06 0x45 $user_id_hex 0xff $hex_username"
    
    cecho "$BLUE" "生成的命令:"
    echo "ipmitool raw $command"
    
    # 额外显示等效的用户友好命令
    cecho "$GREEN" "等效命令:"
    echo "ipmitool user set name $user_id '$username'"
}

# 编码：设置用户权限
encode_user_priv() {
    local user_id=$1
    local privilege=$2
    local channel=${3:-1}
    
    local user_id_hex=$(dec_to_hex $user_id)
    local channel_hex=$(dec_to_hex $channel)
    
    # 权限映射
    case "${privilege,,}" in
        "callback") privilege_hex="0x01" ;;
        "user") privilege_hex="0x02" ;;
        "operator") privilege_hex="0x03" ;;
        "admin"|"administrator") privilege_hex="0x04" ;;
        "oem") privilege_hex="0x05" ;;
        "no_access") privilege_hex="0x0f" ;;
        *) 
            cecho "$RED" "错误: 未知的权限级别 '$privilege'"
            echo "可用权限: callback, user, operator, admin, oem, no_access"
            return 1
            ;;
    esac
    
    cecho "$YELLOW" "=== 编码: 设置用户权限 ==="
    cecho "$GREEN" "用户ID: $user_id ($user_id_hex)"
    cecho "$GREEN" "权限: $privilege ($privilege_hex)"
    cecho "$GREEN" "通道: $channel ($channel_hex)"
    
    local command="0x06 0x44 $user_id_hex $privilege_hex $channel_hex"
    
    cecho "$BLUE" "生成的命令:"
    echo "ipmitool raw $command"
    
    cecho "$GREEN" "等效高级命令:"
    echo "ipmitool user priv $user_id $privilege $channel"
}

# 编码：电源控制
encode_power_control() {
    local action=$1
    local delay=${2:-0}
    local delay_hex=$(dec_to_hex $delay)
    
    # 电源命令映射
    case "$action" in
        "power_on") command_hex="0x00 0x02" ;;
        "power_off") command_hex="0x00 0x00" ;;
        "power_reset") command_hex="0x00 0x03" ;;
        "power_status") command_hex="0x00 0x01" ;;
        *) 
            cecho "$RED" "错误: 未知的电源操作 '$action'"
            return $ERROR_UNKNOWN_COMMAND
            ;;
    esac
    
    cecho "$YELLOW" "=== 编码: 电源$action ==="
    cecho "$GREEN" "操作: $action"
    
    if [ "$action" != "power_status" ]; then
        cecho "$GREEN" "延时: $delay 秒 ($delay_hex)"
        local command="$command_hex $delay_hex"
    else
        local command="$command_hex"
    fi
    
    cecho "$BLUE" "生成的命令:"
    echo "ipmitool raw $command"
    
    cecho "$GREEN" "等效高级命令:"
    local advanced_cmd="ipmitool chassis power $(echo $action | sed 's/_status/status/' | sed 's/_/ /')"
    echo "$advanced_cmd"
}

# 编码：设置用户密码
encode_user_set_password() {
    local user_id=$1
    local password=$2
    
    # 验证用户ID范围
    validate_number_range "$user_id" 1 255 "用户ID" || return $ERROR_RANGE
    
    # 验证密码长度（IPMI通常限制为20字符）
    if [ ${#password} -gt 20 ]; then
        log $LOG_WARN "密码过长，将被截断为20个字符"
        password="${password:0:20}"
    fi
    
    local user_id_hex=$(dec_to_hex $user_id)
    
    cecho "$YELLOW" "=== 编码: 设置用户密码 ==="
    cecho "$GREEN" "用户ID: $user_id ($user_id_hex)"
    cecho "$GREEN" "密码: ******** (已隐藏)"
    
    local hex_password=$(string_to_hex "$password" 20)
    local command="0x06 0x38 $user_id_hex 0xff $hex_password"
    
    cecho "$BLUE" "生成的命令:"
    echo "ipmitool raw $command"
    
    cecho "$GREEN" "等效高级命令:"
    echo "ipmitool user set password $user_id '<密码>'"
}

# 编码：启用/禁用用户
encode_user_enable_disable() {
    local action=$1
    local user_id=$2
    
    # 验证用户ID范围
    validate_number_range "$user_id" 1 255 "用户ID" || return $ERROR_RANGE
    
    local user_id_hex=$(dec_to_hex $user_id)
    local enable_hex="0x01"
    
    if [ "$action" = "user_disable" ]; then
        enable_hex="0x00"
    fi
    
    cecho "$YELLOW" "=== 编码: ${action//_/ } ==="
    cecho "$GREEN" "用户ID: $user_id ($user_id_hex)"
    cecho "$GREEN" "状态: $(if [ "$action" = "user_enable" ]; then echo "启用"; else echo "禁用"; fi)"
    
    local command="0x06 0x40 $user_id_hex $enable_hex"
    
    cecho "$BLUE" "生成的命令:"
    echo "ipmitool raw $command"
    
    cecho "$GREEN" "等效高级命令:"
    echo "ipmitool user $(if [ "$action" = "user_enable" ]; then echo "enable"; else echo "disable"; fi) $user_id"
}

# 传感器类型映射
declare -A SENSOR_TYPES=( 
    ["temperature"]="0x01" 
    ["voltage"]="0x02" 
    ["current"]="0x03" 
    ["fan"]="0x04" 
    ["physical_security"]="0x05" 
    ["platform_security"]="0x06" 
    ["processor"]="0x07" 
    ["power_supply"]="0x08" 
    ["power_unit"]="0x09" 
    ["cooling_device"]="0x0a" 
    ["other"]="0x0b" 
    ["memory"]="0x0c" 
    ["drive_slot"]="0x0d" 
    ["post_memory_resize"]="0x0e" 
    ["system_firmwares"]="0x0f" 
    ["event_logging_disabled"]="0x10" 
    ["watchdog1"]="0x11" 
    ["system_event"]="0x12" 
    ["critical_interrupt"]="0x13" 
    ["button"]="0x14" 
    ["module_board"]="0x15" 
    ["microcontroller"]="0x16" 
    ["add_in_card"]="0x17" 
    ["chassis"]="0x18" 
    ["chip_set"]="0x19" 
    ["other_fru"]="0x1a" 
    ["cable_interconnect"]="0x1b" 
    ["terminator"]="0x1c" 
    ["system_boot_initiated"]="0x1d" 
    ["boot_error"]="0x1e" 
    ["os_boot"]="0x1f" 
    ["os_critical_stop"]="0x20" 
    ["slot_connector"]="0x21" 
    ["system_acpi_power_state"]="0x22" 
    ["watchdog2"]="0x23" 
    ["platform_alert"]="0x24" 
    ["entity_presence"]="0x25" 
    ["monitor_asic"]="0x26" 
    ["lan"]="0x27" 
    ["management_subsys_health"]="0x28" 
    ["battery"]="0x29" 
    ["session_audit"]="0x2a" 
    ["version_change"]="0x2b" 
    ["fru_state"]="0x2c" 
)

# 编码：传感器命令
encode_sensor_commands() {
    local action=$1
    
    case "$action" in
        "sensor_list")
            cecho "$YELLOW" "=== 编码: 传感器列表 ==="
            local command="0x04 0x2d"
            
            cecho "$BLUE" "生成的命令:"
            echo "ipmitool raw $command"
            
            cecho "$GREEN" "等效高级命令:"
            echo "ipmitool sensor list"
            ;;
        
        "sensor_read")
            local sensor_id=$2
            local sensor_id_hex=$(dec_to_hex $sensor_id)
            
            cecho "$YELLOW" "=== 编码: 读取传感器 ==="
            cecho "$GREEN" "传感器ID: $sensor_id ($sensor_id_hex)"
            
            local command="0x04 0x2d $sensor_id_hex"
            
            cecho "$BLUE" "生成的命令:"
            echo "ipmitool raw $command"
            
            cecho "$GREEN" "等效高级命令:"
            echo "ipmitool sensor reading $sensor_id"
            ;;
        
        "sensor_set_thresh")
            local sensor_id=$2
            local threshold_type=$3
            local value=$4
            
            # 阈值类型映射
            local threshold_hex
            case "${threshold_type,,}"
            in
                "lower_non_critical"|"lnc") threshold_hex="0x01" ;;
                "lower_critical"|"lc") threshold_hex="0x02" ;;
                "lower_non_recoverable"|"lnr") threshold_hex="0x03" ;;
                "upper_non_critical"|"unc") threshold_hex="0x04" ;;
                "upper_critical"|"uc") threshold_hex="0x05" ;;
                "upper_non_recoverable"|"unr") threshold_hex="0x06" ;;
                *) 
                    cecho "$RED" "错误: 未知的阈值类型 '$threshold_type'"
                    return $ERROR_UNKNOWN_COMMAND
                    ;;
            esac
            
            local sensor_id_hex=$(dec_to_hex $sensor_id)
            local value_hex=$(dec_to_hex $value)
            
            cecho "$YELLOW" "=== 编码: 设置传感器阈值 ==="
            cecho "$GREEN" "传感器ID: $sensor_id ($sensor_id_hex)"
            cecho "$GREEN" "阈值类型: $threshold_type ($threshold_hex)"
            cecho "$GREEN" "值: $value ($value_hex)"
            
            local command="0x04 0x27 $sensor_id_hex $threshold_hex $value_hex"
            
            cecho "$BLUE" "生成的命令:"
            echo "ipmitool raw $command"
            ;;
        
        "sensor_type_list")
            cecho "$YELLOW" "=== 传感器类型列表 ==="
            cecho "$GREEN" "可用传感器类型:"
            echo "温度 (temperature) - 0x01"
            echo "电压 (voltage) - 0x02"
            echo "电流 (current) - 0x03"
            echo "风扇 (fan) - 0x04"
            echo "物理安全 (physical_security) - 0x05"
            echo "平台安全 (platform_security) - 0x06"
            echo "处理器 (processor) - 0x07"
            echo "电源供应 (power_supply) - 0x08"
            echo "电源单元 (power_unit) - 0x09"
            echo "冷却设备 (cooling_device) - 0x0a"
            echo "其他 (other) - 0x0b"
            echo "内存 (memory) - 0x0c"
            echo "驱动器插槽 (drive_slot) - 0x0d"
            echo "POST内存调整 (post_memory_resize) - 0x0e"
            echo "系统固件 (system_firmwares) - 0x0f"
            echo "事件日志禁用 (event_logging_disabled) - 0x10"
            echo "看门狗1 (watchdog1) - 0x11"
            echo "系统事件 (system_event) - 0x12"
            echo "严重中断 (critical_interrupt) - 0x13"
            echo "按钮 (button) - 0x14"
            echo "模块/板 (module_board) - 0x15"
            echo "微控制器 (microcontroller) - 0x16"
            echo "附加卡 (add_in_card) - 0x17"
            echo "机箱 (chassis) - 0x18"
            echo "芯片组 (chip_set) - 0x19"
            echo "其他FRU (other_fru) - 0x1a"
            echo "线缆/互连 (cable_interconnect) - 0x1b"
            echo "终结器 (terminator) - 0x1c"
            echo "系统启动开始 (system_boot_initiated) - 0x1d"
            echo "启动错误 (boot_error) - 0x1e"
            echo "操作系统启动 (os_boot) - 0x1f"
            echo "操作系统严重停止 (os_critical_stop) - 0x20"
            echo "插槽/连接器 (slot_connector) - 0x21"
            echo "系统ACPI电源状态 (system_acpi_power_state) - 0x22"
            echo "看门狗2 (watchdog2) - 0x23"
            echo "平台警报 (platform_alert) - 0x24"
            echo "实体存在 (entity_presence) - 0x25"
            echo "监控ASIC (monitor_asic) - 0x26"
            echo "网络 (lan) - 0x27"
            echo "管理子系统健康 (management_subsys_health) - 0x28"
            echo "电池 (battery) - 0x29"
            echo "会话审计 (session_audit) - 0x2a"
            echo "版本变更 (version_change) - 0x2b"
            echo "FRU状态 (fru_state) - 0x2c"
            
            cecho "$BLUE" "等效高级命令:"
            echo "ipmitool sdr type"
            ;;
        
        "sensor_by_type")
            local sensor_type=$2
            local type_hex=${SENSOR_TYPES["$sensor_type"]}
            
            if [ -z "$type_hex" ]; then
                cecho "$RED" "错误: 未知的传感器类型 '$sensor_type'"
                cecho "$YELLOW" "请使用 sensor_type_list 查看支持的传感器类型"
                return $ERROR_UNKNOWN_COMMAND
            fi
            
            cecho "$YELLOW" "=== 编码: 按类型查询传感器 ==="
            cecho "$GREEN" "传感器类型: $sensor_type ($type_hex)"
            
            local command="0x04 0x2d 0x00 0x00 $type_hex"
            
            cecho "$BLUE" "生成的命令:"
            echo "ipmitool raw $command"
            
            cecho "$GREEN" "等效高级命令:"
            echo "ipmitool sdr type $type_hex"
            ;;
        
        *)
            cecho "$RED" "错误: 未知的传感器命令 '$action'"
            return $ERROR_UNKNOWN_COMMAND
            ;;
    esac
}

# 编码：SEL日志命令
encode_sel_commands() {
    local action=$1
    
    case "$action" in
        "sel_list")
            cecho "$YELLOW" "=== 编码: SEL日志列表 ==="
            local command="0x0a 0x43 0x00 0x00 0x00 0x00 0xff 0xff"
            
            cecho "$BLUE" "生成的命令:"
            echo "ipmitool raw $command"
            
            cecho "$GREEN" "等效高级命令:"
            echo "ipmitool sel list"
            ;;
        
        "sel_clear")
            cecho "$YELLOW" "=== 编码: 清除SEL日志 ==="
            local command="0x0a 0x47 0x00"
            
            cecho "$BLUE" "生成的命令:"
            echo "ipmitool raw $command"
            
            cecho "$GREEN" "等效高级命令:"
            echo "ipmitool sel clear"
            ;;
        
        "sel_add")
            local event_data=$2
            
            cecho "$YELLOW" "=== 编码: 添加SEL事件 ==="
            cecho "$GREEN" "事件数据: $event_data"
            
            local command="0x0a 0x44 $event_data"
            
            cecho "$BLUE" "生成的命令:"
            echo "ipmitool raw $command"
            ;;
        
        *)
            cecho "$RED" "错误: 未知的SEL命令 '$action'"
            return $ERROR_UNKNOWN_COMMAND
            ;;
    esac
}

# 编码：FRU信息命令
encode_fru_commands() {
    local action=$1
    
    case "$action" in
        "fru_print")
            cecho "$YELLOW" "=== 编码: FRU信息打印 ==="
            local command="0x08 0x10 0x00 0x00"
            
            cecho "$BLUE" "生成的命令:"
            echo "ipmitool raw $command"
            
            cecho "$GREEN" "等效高级命令:"
            echo "ipmitool fru print"
            ;;
        
        "fru_read")
            local device_id=$2
            local device_id_hex=$(dec_to_hex $device_id)
            
            cecho "$YELLOW" "=== 编码: 读取FRU设备 ==="
            cecho "$GREEN" "设备ID: $device_id ($device_id_hex)"
            
            local command="0x08 0x10 $device_id_hex 0x00"
            
            cecho "$BLUE" "生成的命令:"
            echo "ipmitool raw $command"
            
            cecho "$GREEN" "等效高级命令:"
            echo "ipmitool fru print $device_id"
            ;;
        
        *)
            cecho "$RED" "错误: 未知的FRU命令 '$action'"
            return $ERROR_UNKNOWN_COMMAND
            ;;
    esac
}

# 编码：网络配置命令
encode_lan_commands() {
    local action=$1
    local channel=${2:-1}
    
    # 验证通道范围
    validate_number_range "$channel" 1 15 "通道" || return $ERROR_RANGE
    
    case "$action" in
        "lan_print")
            cecho "$YELLOW" "=== 编码: 网络配置打印 ==="
            cecho "$GREEN" "通道: $channel"
            
            local command="0x0c 0x01 0x00 0x00"
            
            cecho "$BLUE" "生成的命令:"
            echo "ipmitool raw $command"
            
            cecho "$GREEN" "等效高级命令:"
            echo "ipmitool lan print $channel"
            ;;
        
        "lan_set_ip")
            local ip_address=$3
            
            cecho "$YELLOW" "=== 编码: 设置IP地址 ==="
            cecho "$GREEN" "通道: $channel"
            cecho "$GREEN" "IP地址: $ip_address"
            
            # 转换IP地址为十六进制
            IFS=. read -r a b c d <<< "$ip_address"
            local ip_hex="0x$(printf '%02x' $a) 0x$(printf '%02x' $b) 0x$(printf '%02x' $c) 0x$(printf '%02x' $d)"
            
            local channel_hex=$(dec_to_hex $channel)
            local command="0x0c 0x02 $channel_hex 0x01 $ip_hex"
            
            cecho "$BLUE" "生成的命令:"
            echo "ipmitool raw $command"
            
            cecho "$GREEN" "等效高级命令:"
            echo "ipmitool lan set $channel ipaddr $ip_address"
            ;;
        
        "lan_set_netmask")
            local netmask=$3
            
            cecho "$YELLOW" "=== 编码: 设置子网掩码 ==="
            cecho "$GREEN" "通道: $channel"
            cecho "$GREEN" "子网掩码: $netmask"
            
            # 转换子网掩码为十六进制
            IFS=. read -r a b c d <<< "$netmask"
            local netmask_hex="0x$(printf '%02x' $a) 0x$(printf '%02x' $b) 0x$(printf '%02x' $c) 0x$(printf '%02x' $d)"
            
            local channel_hex=$(dec_to_hex $channel)
            local command="0x0c 0x02 $channel_hex 0x02 $netmask_hex"
            
            cecho "$BLUE" "生成的命令:"
            echo "ipmitool raw $command"
            
            cecho "$GREEN" "等效高级命令:"
            echo "ipmitool lan set $channel netmask $netmask"
            ;;
        
        "lan_set_gateway")
            local gateway=$3
            
            cecho "$YELLOW" "=== 编码: 设置网关 ==="
            cecho "$GREEN" "通道: $channel"
            cecho "$GREEN" "网关地址: $gateway"
            
            # 转换网关地址为十六进制
            IFS=. read -r a b c d <<< "$gateway"
            local gateway_hex="0x$(printf '%02x' $a) 0x$(printf '%02x' $b) 0x$(printf '%02x' $c) 0x$(printf '%02x' $d)"
            
            local channel_hex=$(dec_to_hex $channel)
            local command="0x0c 0x02 $channel_hex 0x03 $gateway_hex"
            
            cecho "$BLUE" "生成的命令:"
            echo "ipmitool raw $command"
            
            cecho "$GREEN" "等效高级命令:"
            echo "ipmitool lan set $channel defgw ipaddr $gateway"
            ;;
        
        *)
            cecho "$RED" "错误: 未知的网络命令 '$action'"
            return $ERROR_UNKNOWN_COMMAND
            ;;
    esac
}

# 十六进制转字符串（安全优化版）
hex_to_string() {
    local hex_str="$1"
    local result=""
    
    # 检查是否有正常的xxd命令
    if command -v xxd &> /dev/null; then
        log $LOG_DEBUG "使用系统xxd进行十六进制转字符串"
        # 使用xxd并添加安全检查
        result=$(echo -n "$hex_str" | xxd -r -p 2>/dev/null)
        if [ $? -ne 0 ]; then
            log $LOG_WARN "xxd解码失败，尝试备用方法"
            result="无法解码"
        fi
    else
        log $LOG_DEBUG "使用纯bash实现进行十六进制转字符串"
        # 验证十六进制格式
        if ! validate_hex_format "$hex_str" false; then
            echo "无法解码"
            return $ERROR_INVALID_PARAMS
        fi
        
        # 优化的纯bash解码实现
        result=""
        local i=0
        local len=${#hex_str}
        
        # 确保长度是偶数
        if [ $((len % 2)) -ne 0 ]; then
            log $LOG_WARN "十六进制字符串长度不是偶数，添加前导零"
            hex_str="0$hex_str"
            len=${#hex_str}
        fi
        
        while [ $i -lt $len ]; do
            local hex_byte="${hex_str:$i:2}"
            # 使用printf进行安全的十六进制到字符的转换
            result+=$(printf "\\x$hex_byte")
            i=$((i+2))
        done
    fi
    
    echo "$result"
}

# 解码函数（增强版）
decode_command() {
    local hex_string="$1"
    local hex_array
    
    cecho "$YELLOW" "=== 解码IPMI命令 ==="
    cecho "$GREEN" "输入: $hex_string"
    
    # 安全地转换为数组并验证
    read -ra hex_array <<< "$hex_string"
    if [ ${#hex_array[@]} -lt 2 ]; then
        log $LOG_ERROR "十六进制字符串格式错误，至少需要2个字节"
        return $ERROR_INVALID_PARAMS
    fi
    
    local netfn_lun="${hex_array[0]}"
    local command_code="${hex_array[1]}"
    
    # 验证十六进制格式
    validate_hex_format "$netfn_lun" || return $ERROR_INVALID_PARAMS
    validate_hex_format "$command_code" || return $ERROR_INVALID_PARAMS
    
    cecho "$BLUE" "基本信息:"
    echo "NetFn/LUN: $netfn_lun"
    echo "命令代码: $command_code"
    
    # 命令识别
    local command_name="unknown"
    case "$netfn_lun $command_code" in
        # 用户管理命令
        "0x06 0x45")
            command_name="user_set_name"
            cecho "$GREEN" "命令类型: 设置用户名"
            ;;
        "0x06 0x44")
            command_name="user_priv" 
            cecho "$GREEN" "命令类型: 设置用户权限"
            ;;
        "0x06 0x38")
            command_name="user_set_password"
            cecho "$GREEN" "命令类型: 设置用户密码"
            ;;
        "0x06 0x40")
            command_name="user_enable_disable"
            cecho "$GREEN" "命令类型: 启用/禁用用户"
            ;;
        
        # 电源控制命令
        "0x00 0x00")
            command_name="power_off"
            cecho "$GREEN" "命令类型: 关机"
            ;;
        "0x00 0x01")
            command_name="power_status"
            cecho "$GREEN" "命令类型: 电源状态"
            ;;
        "0x00 0x02")
            command_name="power_on"
            cecho "$GREEN" "命令类型: 开机"
            ;;
        "0x00 0x03")
            command_name="power_reset"
            cecho "$GREEN" "命令类型: 重启"
            ;;
        
        # 传感器命令
        "0x04 0x2d")
            command_name="sensor_read"
            cecho "$GREEN" "命令类型: 读取传感器"
            ;;
        "0x04 0x27")
            command_name="sensor_set_threshold"
            cecho "$GREEN" "命令类型: 设置传感器阈值"
            ;;
        
        # SEL命令
        "0x0a 0x43")
            command_name="sel_list"
            cecho "$GREEN" "命令类型: SEL日志列表"
            ;;
        "0x0a 0x47")
            command_name="sel_clear"
            cecho "$GREEN" "命令类型: 清除SEL日志"
            ;;
        "0x0a 0x44")
            command_name="sel_add"
            cecho "$GREEN" "命令类型: 添加SEL事件"
            ;;
        
        # FRU命令
        "0x08 0x10")
            command_name="fru_read"
            cecho "$GREEN" "命令类型: 读取FRU信息"
            ;;
        
        # 网络命令
        "0x0c 0x01")
            command_name="lan_print"
            cecho "$GREEN" "命令类型: 网络配置打印"
            ;;
        "0x0c 0x02")
            command_name="lan_set"
            cecho "$GREEN" "命令类型: 设置网络配置"
            ;;
        
        # 默认情况
        *)
            cecho "$YELLOW" "命令类型: 未知"
            ;;
    esac
    
    echo ""
    cecho "$BLUE" "详细解析:"
    
    # 根据命令类型进行解析，添加参数验证
    case "$command_name" in
        user_set_name)
            # 验证参数数量
            if [ ${#hex_array[@]} -lt 5 ]; then
                log $LOG_ERROR "用户设置命令格式不完整"
                return $ERROR_INVALID_PARAMS
            fi
            
            local user_id_hex="${hex_array[2]}"
            validate_hex_format "$user_id_hex" || return $ERROR_INVALID_PARAMS
            
            local user_id=$((16#${user_id_hex#0x}))
            # 验证用户ID范围
            validate_number_range "$user_id" 1 255 "用户ID" || return $ERROR_RANGE
            
            cecho "$GREEN" "用户ID: $user_id ($user_id_hex)"
            
            # 提取用户名（跳过第3个字节）
            local username_hex=""
            for ((i=4; i<${#hex_array[@]}; i++)); do
                local byte="${hex_array[$i]}"
                [ "$byte" = "0x00" ] && break  # 遇到0x00表示字符串结束
                username_hex="$username_hex${byte#0x}"
            done
            
            log $LOG_DEBUG "提取到的用户名十六进制: $username_hex"
            
            # 使用优化的解码函数
            local username=$(hex_to_string "$username_hex")
            cecho "$GREEN" "用户名: $username"
            ;;
            
        user_priv)
            # 验证参数数量
            if [ ${#hex_array[@]} -lt 5 ]; then
                log $LOG_ERROR "用户权限命令格式不完整"
                return $ERROR_INVALID_PARAMS
            fi
            
            local user_id_hex="${hex_array[2]}"
            local priv_hex="${hex_array[3]}"
            local channel_hex="${hex_array[4]}"
            
            # 验证所有十六进制参数
            validate_hex_format "$user_id_hex" || return $ERROR_INVALID_PARAMS
            validate_hex_format "$priv_hex" || return $ERROR_INVALID_PARAMS
            validate_hex_format "$channel_hex" || return $ERROR_INVALID_PARAMS
            
            local user_id=$((16#${user_id_hex#0x}))
            local channel=$((16#${channel_hex#0x}))
            
            # 验证范围
            validate_number_range "$user_id" 1 255 "用户ID" || return $ERROR_RANGE
            validate_number_range "$channel" 0 255 "通道" || return $ERROR_RANGE
            
            cecho "$GREEN" "用户ID: $user_id ($user_id_hex)"
            cecho "$GREEN" "通道: $channel ($channel_hex)"
            
            # 权限识别
            local priv_name="未知"
            case "$priv_hex" in
                "0x01") priv_name="callback" ;;
                "0x02") priv_name="user" ;;
                "0x03") priv_name="operator" ;;
                "0x04") priv_name="admin" ;;
                "0x05") priv_name="oem" ;;
                "0x0f") priv_name="no_access" ;;
            esac
            cecho "$GREEN" "权限: $priv_name ($priv_hex)"
            ;;
            
        power_on|power_off|power_reset)
            # 验证参数数量
            if [ ${#hex_array[@]} -lt 3 ]; then
                log $LOG_ERROR "电源命令格式不完整"
                return $ERROR_INVALID_PARAMS
            fi
            
            local delay_hex="${hex_array[2]}"
            validate_hex_format "$delay_hex" || return $ERROR_INVALID_PARAMS
            
            local delay=$((16#${delay_hex#0x}))
            # 验证延时范围（合理范围：0-65535秒）
            if [ "$delay" -gt 65535 ]; then
                log $LOG_WARN "延时值 $delay 过大，可能超出设备支持范围"
            fi
            
            cecho "$GREEN" "延时: $delay 秒 ($delay_hex)"
            ;;
            
        user_set_password)
            # 验证参数数量
            if [ ${#hex_array[@]} -lt 5 ]; then
                log $LOG_ERROR "用户密码设置命令格式不完整"
                return $ERROR_INVALID_PARAMS
            fi
            
            local user_id_hex="${hex_array[2]}"
            validate_hex_format "$user_id_hex" || return $ERROR_INVALID_PARAMS
            
            local user_id=$((16#${user_id_hex#0x}))
            validate_number_range "$user_id" 1 255 "用户ID" || return $ERROR_RANGE
            
            cecho "$GREEN" "用户ID: $user_id ($user_id_hex)"
            cecho "$GREEN" "密码: ******** (已隐藏)"
            ;;
            
        user_enable_disable)
            # 验证参数数量
            if [ ${#hex_array[@]} -lt 4 ]; then
                log $LOG_ERROR "用户启用/禁用命令格式不完整"
                return $ERROR_INVALID_PARAMS
            fi
            
            local user_id_hex="${hex_array[2]}"
            local enable_hex="${hex_array[3]}"
            
            validate_hex_format "$user_id_hex" || return $ERROR_INVALID_PARAMS
            validate_hex_format "$enable_hex" || return $ERROR_INVALID_PARAMS
            
            local user_id=$((16#${user_id_hex#0x}))
            validate_number_range "$user_id" 1 255 "用户ID" || return $ERROR_RANGE
            
            local status="禁用"
            [ "$enable_hex" = "0x01" ] && status="启用"
            
            cecho "$GREEN" "用户ID: $user_id ($user_id_hex)"
            cecho "$GREEN" "状态: $status ($enable_hex)"
            ;;
            
        power_status)
            cecho "$GREEN" "电源状态查询命令"
            ;;
            
        sensor_read)
            cecho "$GREEN" "传感器ID: ${hex_array[2]}"
            if [ ${#hex_array[@]} -gt 3 ]; then
                cecho "$GREEN" "传感器数据: ${hex_array[*]:3}"
            fi
            ;;
            
        sensor_set_threshold)
            if [ ${#hex_array[@]} -ge 5 ]; then
                cecho "$GREEN" "传感器ID: ${hex_array[2]}"
                cecho "$GREEN" "阈值类型: ${hex_array[3]}"
                cecho "$GREEN" "阈值: ${hex_array[4]}"
            fi
            ;;
            
        sel_list)
            cecho "$GREEN" "SEL日志列表查询命令"
            ;;
            
        sel_clear)
            cecho "$GREEN" "SEL日志清除命令"
            ;;
            
        sel_add)
            cecho "$GREEN" "SEL事件添加命令"
            if [ ${#hex_array[@]} -gt 3 ]; then
                cecho "$GREEN" "事件数据: ${hex_array[*]:3}"
            fi
            ;;
            
        fru_read)
            cecho "$GREEN" "FRU设备ID: ${hex_array[2]}"
            ;;
            
        lan_print)
            cecho "$GREEN" "网络配置打印命令"
            ;;
            
        lan_set)
            if [ ${#hex_array[@]} -ge 4 ]; then
                cecho "$GREEN" "通道: ${hex_array[2]}"
                cecho "$GREEN" "配置类型: ${hex_array[3]}"
                if [ ${#hex_array[@]} -ge 8 ]; then
                    # 解析IP地址
                    local ip_parts=(${hex_array[@]:4:4})
                    local ip_str=""
                    for part in "${ip_parts[@]}"; do
                        local dec_val=$((16#${part#0x}))
                        ip_str="$ip_str$dec_val."
                    done
                    ip_str="${ip_str%.}"  # 移除末尾的点
                    cecho "$GREEN" "IP地址: $ip_str"
                fi
            fi
            ;;
            
        *)
            cecho "$GREEN" "数据字节: ${hex_array[*]:2}"
            # 显示原始字节的十进制值，方便调试
            if [ ${#hex_array[@]} -gt 2 ]; then
                local decimal_values=""
                for ((i=2; i<${#hex_array[@]}; i++)); do
                    local hex_byte="${hex_array[$i]}"
                    local dec_val=$((16#${hex_byte#0x}))
                    decimal_values="$decimal_values $dec_val"
                done
                cecho "$BLUE" "十进制值:${decimal_values}"
            fi
            ;;
    esac
    
    echo ""
    cecho "$BLUE" "完整命令:"
    echo "ipmitool raw $hex_string"
}

# 命令执行功能（新增）
execute_command() {
    local command="$1"
    
    log $LOG_INFO "准备执行命令: $command"
    
    # 检查ipmitool是否可用
    if ! command -v ipmitool &> /dev/null; then
        log $LOG_ERROR "ipmitool 命令未找到，请先安装: apt-get install ipmitool"
        return $ERROR_DEPENDENCY
    fi
    
    # 显示执行提示
    cecho "$YELLOW" "执行命令中..."
    
    # 实际执行命令并捕获结果
    local result
    result=$(eval "$command" 2>&1)
    local exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        cecho "$GREEN" "命令执行成功!"
        if [ -n "$result" ]; then
            cecho "$BLUE" "执行结果:"
            echo "$result"
        fi
        return 0
    else
        log $LOG_ERROR "命令执行失败 (退出码: $exit_code)"
        cecho "$RED" "错误信息:"
        echo "$result"
        return $ERROR_EXECUTION
    fi
}

# 主函数（增强版）
main() {
    # 捕获退出信号，进行清理
    trap 'log $LOG_INFO "脚本退出"; exit $?' INT TERM
    
    log $LOG_DEBUG "脚本启动，参数: $@"
    
    if [ $# -lt 1 ]; then
        log $LOG_WARN "未提供参数"
        usage
        exit $ERROR_INVALID_PARAMS
    fi
    
    local mode=$1
    shift
    
    # 新增: 执行模式选项
    local execute_flag=false
    
    # 处理全局选项
    while [[ $1 == -* ]]; do
        case "$1" in
            --execute|-x)
                execute_flag=true
                shift
                ;;
            --debug)
                LOG_LEVEL=$LOG_DEBUG
                log $LOG_DEBUG "调试模式已启用"
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                log $LOG_ERROR "未知的选项: $1"
                usage
                exit $ERROR_INVALID_PARAMS
                ;;
        esac
    done
    
    case "$mode" in
        encode|e)
            if [ $# -lt 1 ]; then
                log $LOG_ERROR "编码模式需要指定命令类型"
                usage
                exit $ERROR_INVALID_PARAMS
            fi
            
            local command_type=$1
            shift
            
            case "$command_type" in
                user_set_name)
                    if [ $# -ne 2 ]; then
                        log $LOG_ERROR "需要用户ID和用户名"
                        usage
                        exit $ERROR_INVALID_PARAMS
                    fi
                    encode_user_set_name "$1" "$2"
                    ;;
                user_priv)
                    if [ $# -lt 2 ]; then
                        log $LOG_ERROR "需要用户ID和权限级别"
                        usage
                        exit $ERROR_INVALID_PARAMS
                    fi
                    encode_user_priv "$1" "$2" "$3"
                    ;;
                power_on|power_off|power_reset|power_status)
                    encode_power_control "$command_type" "$1"
                    ;;
                    
                # 用户管理命令
                user_set_password)
                    if [ $# -ne 2 ]; then
                        log $LOG_ERROR "需要用户ID和密码"
                        usage
                        exit $ERROR_INVALID_PARAMS
                    fi
                    encode_user_set_password "$1" "$2"
                    ;;
                    
                user_enable|user_disable)
                    if [ $# -ne 1 ]; then
                        log $LOG_ERROR "需要用户ID"
                        usage
                        exit $ERROR_INVALID_PARAMS
                    fi
                    encode_user_enable_disable "$command_type" "$1"
                    ;;
                    
                # 传感器命令
                sensor_list|sensor_read|sensor_set_thresh|sensor_type_list|sensor_by_type)
                    encode_sensor_commands "$command_type" "$@"
                    ;;
                    
                # SEL命令
                sel_list|sel_clear|sel_add)
                    encode_sel_commands "$command_type" "$@"
                    ;;
                    
                # FRU命令
                fru_print|fru_read)
                    encode_fru_commands "$command_type" "$@"
                    ;;
                    
                # 网络命令
                lan_print|lan_set_ip|lan_set_netmask|lan_set_gateway)
                    encode_lan_commands "$command_type" "$@"
                    ;;
                    
                *)
                    log $LOG_ERROR "未知命令类型: $command_type"
                    usage
                    exit $ERROR_UNKNOWN_COMMAND
                    ;;
            esac
            
            # 如果启用了执行模式，执行生成的命令
            if [ "$execute_flag" = true ] && [ -n "$command" ]; then
                execute_command "$command"
                exit $?
            fi
            ;;
            
        decode|d)
            if [ $# -ne 1 ]; then
                log $LOG_ERROR "需要十六进制字符串"
                usage
                exit $ERROR_INVALID_PARAMS
            fi
            decode_command "$1"
            ;;
            
        help|--help|-h)
            usage
            ;;
            
        *)
            log $LOG_ERROR "未知模式: $mode"
            usage
            exit $ERROR_UNKNOWN_COMMAND
            ;;
    esac
    
    log $LOG_DEBUG "脚本执行完成"
    return 0
}

# 检查依赖并提供xxd备用实现（增强版）
check_deps() {
    log $LOG_DEBUG "检查系统依赖"
    
    # 检查是否需要定义xxd备用函数
    if ! command -v xxd &> /dev/null; then
        log $LOG_WARN "xxd 命令未找到，将使用内置实现"
        cecho "$YELLOW" "警告: xxd 命令未找到，将使用内置的备用实现"
    fi
    
    # 检查其他必要命令
    for cmd in printf echo od tr fold; do
        if ! command -v $cmd &> /dev/null; then
            log $LOG_WARN "命令 '$cmd' 未找到，某些备用功能可能受限"
        fi
    done
    
    log $LOG_DEBUG "依赖检查完成"
    return 0
}

# 启动
check_deps
main "$@"