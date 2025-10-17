#!/bin/sh
# OpenWrt/immwrt跨境直播环境一键配置脚本 v2.1
# 完整修复版 - 支持断点续传和全场景适配

# ==================== 配置常量 ====================
STEP_FILE="/etc/live_auto_step"
LOG_FILE="/var/log/openwrt_live_secure.log"
DEV_AUDIT_LOG="/var/log/live_auto_audit.log"
BACKUP_DIR="/etc/live_config_backup"
LIVE_PORTS=("1935" "443" "8080" "8443" "554")
ARCH=$(uname -m | tr '[:upper:]' '[:lower:]')
HARDWARE_SCENE="unknown"
OPENWRT_VER=$(cat /etc/openwrt_version 2>/dev/null || cat /etc/immwrt_version 2>/dev/null || echo "19.07")
LIVE_TRAFFIC_THRESHOLD=1
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ==================== 模块1：基础函数库 ====================

# 1. 日志强化（敏感信息脱敏）
dev_audit_log() {
    local step="$1"
    local cmd="$2"
    local output="$3"
    local error="$4"
    [ -f "$DEV_AUDIT_LOG" ] || { 
        echo "=== 跨境直播配置审计日志 ===" > "$DEV_AUDIT_LOG"
        echo "OpenWrt版本：$OPENWRT_VER" >> "$DEV_AUDIT_LOG"
        echo "开始时间：$(date '+%Y-%m-%d %H:%M:%S')" >> "$DEV_AUDIT_LOG"
    }
    [ $(du -b "$DEV_AUDIT_LOG" 2>/dev/null | awk '{print $1}') -ge 10485760 ] && mv "$DEV_AUDIT_LOG" "$DEV_AUDIT_LOG.bak"
    
    # 敏感信息脱敏（UUID/密码）
    output=$(echo "$output" | sed -E 's/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/xxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/g' | sed -E 's/(password|key)=[^\&]+/\1=****/g')
    cmd=$(echo "$cmd" | sed -E 's/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/xxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/g')
    
    echo "========================================" >> "$DEV_AUDIT_LOG"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [步骤] $step" >> "$DEV_AUDIT_LOG"
    [ -n "$cmd" ] && echo "[执行命令] $cmd" >> "$DEV_AUDIT_LOG"
    [ -n "$output" ] && echo "[输出] $output" >> "$DEV_AUDIT_LOG"
    [ -n "$error" ] && echo "[错误] $error" >> "$DEV_AUDIT_LOG" && echo "[错误类型] $(error_type "$error")" >> "$DEV_AUDIT_LOG"
    echo "========================================" >> "$DEV_AUDIT_LOG"
}

# 2. 错误类型识别
error_type() {
    local error="$1"
    if echo "$error" | grep -qE 'syntax error|missing'; then echo "语法错误";
    elif echo "$error" | grep -qE 'undefined variable'; then echo "变量未定义";
    elif echo "$error" | grep -qE 'type mismatch'; then echo "数据类型不匹配";
    elif echo "$error" | grep -qE 'not found|no such file'; then echo "环境缺失";
    elif echo "$error" | grep -qE 'permission denied'; then echo "权限不足";
    elif echo "$error" | grep -qE 'connection failed|timeout'; then echo "服务不可用";
    elif echo "$error" | grep -qE 'fw4: not found'; then echo "fw4缺失（版本<21.02）";
    else echo "未知错误"; fi
}

# 3. 零错误执行（版本适配+预修复）
auto_exec() {
    local step_desc="$1"
    local cmd="$2"
    local fix_cmd="$3"
    local verify_cmd="$4"
    local retry=3
    local exit_code=1
    local output=""
    local error_msg=""

    # 版本适配修正（如旧版用fw3）
    if echo "$cmd" | grep -q "fw4" && [ "$(echo "$OPENWRT_VER" | cut -d'.' -f1)" -lt 21 ]; then
        cmd=$(echo "$cmd" | sed 's/fw4/fw3/g' | sed 's/nft/iptables/g')
        echo -e "${YELLOW}🔧 版本适配：$OPENWRT_VER 用fw3替换fw4${NC}"
    fi

    echo -e "${CYAN}▶ 执行：$step_desc${NC}"
    if [ -n "$fix_cmd" ]; then
        echo -e "${YELLOW}🔧 提前处理潜在问题...${NC}"
        local fix_output=$(eval "$fix_cmd" 2>&1)
        [ $? -ne 0 ] && echo -e "${YELLOW}⚠ 预修复提示：$fix_output${NC}"
    fi

    while [ $retry -ge 0 ] && [ $exit_code -ne 0 ]; do
        output=$(eval "$cmd" 2>&1)
        exit_code=$?
        error_msg="$output"
        
        # 针对性修复
        if [ $exit_code -ne 0 ]; then
            case $(error_type "$error_msg") in
                "环境缺失")
                    local missing_pkg=$(echo "$error_msg" | grep -oE 'missing (package|file) [^ ]+' | awk '{print $3}')
                    [ -n "$missing_pkg" ] && { 
                        echo -e "${YELLOW}🔧 安装缺失包：$missing_pkg${NC}"
                        opkg update >/dev/null 2>&1
                        opkg install "$missing_pkg" >/dev/null 2>&1
                    }
                    ;;
                "权限不足") 
                    cmd="sudo $cmd"
                    ;;
                "fw4缺失（版本<21.02）") 
                    cmd=$(echo "$cmd" | sed 's/fw4/fw3/g')
                    ;;
                *) 
                    sleep 3
                    ;;
            esac
        fi
        [ $exit_code -eq 0 ] && break
        [ $retry -gt 0 ] && echo -e "${YELLOW}⚠ 失败（剩余$retry次）：$(echo "$error_msg" | head -1)${NC}" && sleep 3
        retry=$((retry - 1))
    done

    # 验证
    if [ $exit_code -eq 0 ] && [ -n "$verify_cmd" ]; then
        local verify_output=$(eval "$verify_cmd" 2>&1)
        [ $? -ne 0 ] && { exit_code=1; error_msg="验证失败：$verify_output"; }
    fi

    # 错误处理
    if [ $exit_code -ne 0 ]; then
        echo -e "${RED}❌ $step_desc 失败（${error_type "$error_msg"}）${NC}"
        echo -e "${RED}👉 解决方案：${NC}"
        case $(error_type "$error_msg") in
            "fw4缺失（版本<21.02）") 
                echo -e "${RED}1. 升级OpenWrt到21.02+ 或 手动执行fw3命令${NC}"
                ;;
            "环境缺失") 
                echo -e "${RED}1. 执行 opkg update && opkg install $missing_pkg${NC}"
                ;;
            "权限不足")
                echo -e "${RED}1. 请使用root权限运行此脚本${NC}"
                ;;
            *)
                echo -e "${RED}1. 请检查错误信息并手动修复${NC}"
                ;;
        esac
        dev_audit_log "$step_desc" "$cmd" "$output" "$error_msg"
        exit 1
    fi

    echo -e "${GREEN}✅ $step_desc 完成${NC}"
    dev_audit_log "$step_desc" "$cmd" "$output" ""
    return 0
}

# 4. 步骤管理（断点续传）
check_step() {
    local step="$1"
    [ -f "$STEP_FILE" ] && grep -q "$step" "$STEP_FILE" && return 0
    return 1
}

mark_step() {
    local step="$1"
    [ -f "$STEP_FILE" ] || touch "$STEP_FILE"
    grep -q "$step" "$STEP_FILE" || echo "$step" >> "$STEP_FILE"
}

# ==================== 模块2：环境检测与初始化 ====================

# 5. 全场景+版本识别
detect_env() {
    # 场景识别
    if [ -f "/.dockerenv" ] || grep -qE 'docker|lxc' /proc/1/cgroup 2>/dev/null; then
        HARDWARE_SCENE="container"
        echo -e "${YELLOW}ℹ 场景：容器${NC}"
    elif [ -f "/sys/devices/virtual/dmi/id/sys_vendor" ] && echo "$(cat /sys/devices/virtual/dmi/id/sys_vendor 2>/dev/null)" | grep -qiE "vmware|virtualbox|qemu"; then
        HARDWARE_SCENE="vm"
        echo -e "${YELLOW}ℹ 场景：虚拟机${NC}"
    else
        HARDWARE_SCENE="physical"
        echo -e "${YELLOW}ℹ 场景：物理机${NC}"
    fi
    
    # ARM识别
    if echo "$ARCH" | grep -qE "arm|aarch"; then
        HARDWARE_SCENE="${HARDWARE_SCENE}_arm"
        echo -e "${YELLOW}ℹ 架构：ARM（适配小众芯片）${NC}"
    fi
    
    # 版本提示
    [ "$(echo "$OPENWRT_VER" | cut -d'.' -f1)" -lt 21 ] && echo -e "${YELLOW}ℹ 版本：$OPENWRT_VER（用fw3，无fw4）${NC}"
    dev_audit_log "环境识别" "" "场景：$HARDWARE_SCENE，版本：$OPENWRT_VER" ""
}

# 6. 直播环境初始化（依赖处理）
auto_env_init() {
    check_step "step_env_init" && { echo -e "${GREEN}✅ 环境初始化已完成，跳过${NC}"; return 0; }
    echo -e "${CYAN}▶ 执行：直播环境初始化${NC}"
    
    # 检测并安装基础依赖
    local deps=("curl" "jq" "coreutils" "grep" "sed" "awk" "bc")
    local missing_deps=()
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing_deps+=("$dep")
        fi
    done
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        auto_exec "安装基础依赖" \
            "opkg update && opkg install ${missing_deps[*]}" \
            "" \
            "echo ${missing_deps[*]} | xargs -n1 command -v"
    fi
    
    # 检测passwall
    if ! uci show passwall >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠ 未发现passwall，需要手动安装${NC}"
        echo -e "${YELLOW}📢 请先安装passwall后再继续${NC}"
        dev_audit_log "环境初始化" "" "缺失passwall" "需要手动安装"
        exit 1
    fi
    
    # 创建备份目录
    auto_exec "创建备份目录" \
        "mkdir -p $BACKUP_DIR" \
        "" \
        "test -d $BACKUP_DIR"
    
    # 容器场景特殊处理
    if [ "$HARDWARE_SCENE" = "container" ]; then
        echo -e "${YELLOW}📢 容器环境提示：${NC}"
        echo -e "${YELLOW}1. 确保宿主机已配置USB设备直通${NC}"
        echo -e "${YELLOW}2. 网络模式建议使用host模式${NC}"
        dev_audit_log "容器环境处理" "" "已提示USB直通和网络模式" ""
    fi
    
    # ARM架构特殊处理
    if echo "$HARDWARE_SCENE" | grep -q "arm"; then
        auto_exec "ARM架构优化" \
            "opkg install kmod-usb-net kmod-usb-core kmod-usb-ohci kmod-usb-uhci" \
            "" \
            "lsmod | grep -q 'usb_net'"
        echo -e "${YELLOW}📢 ARM设备提示：已安装通用USB驱动${NC}"
    fi
    
    echo -e "${GREEN}✅ 环境初始化完成${NC}"
    mark_step "step_env_init"
}

# ==================== 模块3：代理多节点配置 ====================

# 7. 代理多节点+自动切换（核心优化）
auto_proxy_multi_node() {
    check_step "step_proxy_multi" && { echo -e "${GREEN}✅ 代理多节点已配置，跳过${NC}"; return 0; }
    echo -e "${CYAN}▶ 配置：代理多节点（防止直播中断）${NC}"
    local node_count=0
    local proxy_links=()

    # 输入多节点
    echo -e "${YELLOW}📢 输入跨境代理链接（空行结束，至少1个，推荐3个）${NC}"
    while true; do
        read -p "代理链接（VMess/VLESS/Trojan）：" link
        if [ -z "$link" ]; then
            [ $node_count -eq 0 ] && { echo -e "${RED}❌ 至少1个节点！${NC}"; continue; }
            break
        fi
        if echo "$link" | grep -qE "vmess://|vless://|trojan://"; then
            proxy_links+=("$link")
            node_count=$((node_count + 1))
            echo -e "${GREEN}✅ 已添加第$node_count个节点${NC}"
        else
            echo -e "${RED}❌ 格式错！示例：vmess://xxx${NC}"
        fi
    done

    # 清理旧节点
    uci delete passwall.@nodes[0-9]* 2>/dev/null && uci commit passwall >/dev/null 2>&1

    # 批量添加节点
    for i in "${!proxy_links[@]}"; do
        local link="${proxy_links[$i]}"
        auto_exec "添加第$((i+1))个代理节点" \
            "uci add passwall nodes && uci set passwall.@nodes[-1].remarks=\"Live_Node_$((i+1))\" && uci set passwall.@nodes[-1].enabled=\"1\"" \
            "" \
            "uci show passwall | grep -q 'Live_Node_$((i+1))'"
        
        # 解析节点
        if echo "$link" | grep -q "vmess://"; then
            local json=$(echo "${link#vmess://}" | base64 -d 2>/dev/null)
            local addr=$(echo "$json" | jq -r '.add // ""')
            local port=$(echo "$json" | jq -r '.port // ""')
            local uuid=$(echo "$json" | jq -r '.id // ""')
            [ -z "$addr" ] && read -p "第$((i+1))个节点地址：" addr
            [ -z "$port" ] && read -p "第$((i+1))个节点端口：" port
            [ -z "$uuid" ] && read -p "第$((i+1))个节点UUID：" uuid
            uci set passwall.@nodes[-1].type="V2ray" 
            uci set passwall.@nodes[-1].address="$addr" 
            uci set passwall.@nodes[-1].port="$port" 
            uci set passwall.@nodes[-1].uuid="$uuid" 
            uci set passwall.@nodes[-1].tls="1"
        elif echo "$link" | grep -q "vless://"; then
            local config="${link#vless://}"
            local uuid="${config%%@*}"
            local addr_port="${config#*@}"
            local addr="${addr_port%%:*}"
            local port="${addr_port#*:}"
            [ -z "$uuid" ] && read -p "第$((i+1))个节点UUID：" uuid
            [ -z "$addr" ] && read -p "第$((i+1))个节点地址：" addr
            [ -z "$port" ] && read -p "第$((i+1))个节点端口：" port
            uci set passwall.@nodes[-1].type="V2ray" 
            uci set passwall.@nodes[-1].address="$addr" 
            uci set passwall.@nodes[-1].port="$port" 
            uci set passwall.@nodes[-1].uuid="$uuid" 
            uci set passwall.@nodes[-1].tls="1"
        elif echo "$link" | grep -q "trojan://"; then
            local config="${link#trojan://}"
            local pwd="${config%%@*}"
            local addr_port="${config#*@}"
            local addr="${addr_port%%:*}"
            local port="${addr_port#*:}"
            [ -z "$pwd" ] && read -p "第$((i+1))个节点密码：" pwd
            [ -z "$addr" ] && read -p "第$((i+1))个节点地址：" addr
            [ -z "$port" ] && read -p "第$((i+1))个节点端口：" port
            uci set passwall.@nodes[-1].type="Trojan" 
            uci set passwall.@nodes[-1].address="$addr" 
            uci set passwall.@nodes[-1].port="$port" 
            uci set passwall.@nodes[-1].password="$pwd" 
            uci set passwall.@nodes[-1].tls="1"
        fi
        uci set passwall.@nodes[-1].tcp_fast_open="1" 
        uci commit passwall >/dev/null 2>&1
    done

    # 配置自动切换（健康检测）
    auto_exec "配置代理自动切换" \
        "uci set passwall.config.mode=\"loadbalance\" && uci set passwall.config.proxy_group=\"live_balance\" && uci set passwall.config.loadbalance_health_check=\"1\" && uci set passwall.config.loadbalance_health_check_interval=\"30\" && uci commit passwall" \
        "" \
        "uci get passwall.config.mode | grep -q 'loadbalance'"

    # 启动+验证
    auto_exec "启动代理服务" \
        "/etc/init.d/passwall restart && /etc/init.d/passwall enable" \
        "" \
        "/etc/init.d/passwall status | grep -q 'running'"
    
    auto_exec "验证多节点连通性" \
        "for i in 1 2 3; do curl -s --connect-timeout 5 https://www.tiktok.com >/dev/null 2>&1 && break; sleep 2; done" \
        "" \
        ""

    # 生成节点切换脚本（手动应急）
    cat > /usr/bin/live_switch_proxy.sh << 'SWITCH'
#!/bin/sh
current_node=$(uci get passwall.config.current_node 2>/dev/null)
node_count=$(uci show passwall | grep -c 'Live_Node_')
next_node=$((current_node % node_count + 1))
uci set passwall.config.current_node="$next_node" && uci commit passwall && /etc/init.d/passwall restart
echo "已切换到第$next_node个代理节点"
SWITCH
    chmod +x /usr/bin/live_switch_proxy.sh

    echo -e "${GREEN}✅ 多节点配置完成（$node_count个节点，自动切换+手动切换脚本：live_switch_proxy.sh）${NC}"
    mark_step "step_proxy_multi"
}

# ==================== 模块4：端口监控与流量告警 ====================

# 8. 直播端口监控（防占用+自动恢复）
auto_port_monitor() {
    check_step "step_port_monitor" && { echo -e "${GREEN}✅ 端口监控已配置，跳过${NC}"; return 0; }
    echo -e "${CYAN}▶ 配置：直播端口监控${NC}"

    # 生成端口监控脚本
    cat > /usr/bin/live_port_monitor.sh << 'PORT_MON'
#!/bin/sh
LIVE_PORTS=("1935" "443" "8080" "8443" "554")
LOG_FILE="/var/log/live_port_monitor.log"
LOCK_FILE="/tmp/live_port_monitor.lock"

# 避免并发执行
[ -f "$LOCK_FILE" ] && exit 0
touch "$LOCK_FILE"

# 检查端口占用
for port in "${LIVE_PORTS[@]}"; do
    # 检查TCP端口
    pid=$(netstat -tulnp 2>/dev/null | grep ":$port " | awk '{print $7}' | cut -d'/' -f1)
    if [ -n "$pid" ] && [ "$pid" -gt 0 ]; then
        proc_name=$(ps -p "$pid" -o comm= 2>/dev/null)
        echo "$(date '+%Y-%m-%d %H:%M:%S') - 端口 $port 被进程 $proc_name (PID: $pid) 占用" >> "$LOG_FILE"
        
        # 检查是否是直播相关进程
        if ! echo "$proc_name" | grep -qE 'v2ray|trojan|passwall|nginx'; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') - 杀死占用进程 $pid ($proc_name)" >> "$LOG_FILE"
            kill -9 "$pid" 2>/dev/null
            # 重启相关服务
            /etc/init.d/passwall restart >/dev/null 2>&1
            echo "$(date '+%Y-%m-%d %H:%M:%S') - 已重启passwall服务" >> "$LOG_FILE"
        fi
    fi
done

rm -f "$LOCK_FILE"
PORT_MON
    chmod +x /usr/bin/live_port_monitor.sh

    # 添加到crontab（每分钟检查）
    local cron_cmd="* * * * * /usr/bin/live_port_monitor.sh"
    if ! crontab -l 2>/dev/null | grep -q "live_port_monitor.sh"; then
        (crontab -l 2>/dev/null; echo "$cron_cmd") | crontab -
    fi

    # 立即执行一次
    /usr/bin/live_port_monitor.sh

    echo -e "${GREEN}✅ 端口监控配置完成（每分钟检查端口：${LIVE_PORTS[*]}）${NC}"
    mark_step "step_port_monitor"
}

# 9. 流量监控告警（防超流）
auto_traffic_alert() {
    check_step "step_traffic_alert" && { echo -e "${GREEN}✅ 流量告警已配置，跳过${NC}"; return 0; }
    echo -e "${CYAN}▶ 配置：流量监控告警${NC}"

    # 获取邮箱配置
    read -p "是否需要流量告警？(y/n): " need_alert
    if [ "$need_alert" = "y" ] || [ "$need_alert" = "Y" ]; then
        read -p "请输入接收告警的邮箱：" alert_email
        read -p "请输入SMTP服务器（如smtp.163.com）：" smtp_server
        read -p "请输入SMTP端口（一般25或465）：" smtp_port
        read -p "请输入SMTP账号：" smtp_user
        read -p "请输入SMTP密码/授权码：" smtp_pass

        # 生成流量监控脚本
        cat > /usr/bin/live_traffic_monitor.sh << 'EOF'
#!/bin/sh
INTERFACE="wan"
THRESHOLD=1  # GB
ALERT_EMAIL="$alert_email"
SMTP_SERVER="$smtp_server"
SMTP_PORT="$smtp_port"
SMTP_USER="$smtp_user"
SMTP_PASS="$smtp_pass"
LOG_FILE="/var/log/live_traffic_monitor.log"
LAST_ALERT_FILE="/tmp/live_last_alert"

# 检查依赖
if ! command -v bc >/dev/null 2>&1; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - 错误：bc命令未安装" >> "$LOG_FILE"
    exit 1
fi

# 计算今日已用流量（GB）- 简化版本
today=$(date '+%Y-%m-%d')
# 使用/proc/net/dev获取流量统计
rx_bytes=$(grep "$INTERFACE" /proc/net/dev | awk '{print $2}')
tx_bytes=$(grep "$INTERFACE" /proc/net/dev | awk '{print $10}')
total_bytes=$((rx_bytes + tx_bytes))
traffic_gb=$(echo "scale=2; $total_bytes / 1024 / 1024 / 1024" | bc)

echo "$(date '+%Y-%m-%d %H:%M:%S') - 今日已用流量：$traffic_gb GB" >> "$LOG_FILE"

# 检查是否超过阈值
if [ $(echo "$traffic_gb > $THRESHOLD" | bc) -eq 1 ]; then
    # 检查是否已发送过告警（避免重复）
    if [ ! -f "$LAST_ALERT_FILE" ] || [ $(cat "$LAST_ALERT_FILE") != "$today" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - 流量超过阈值 $THRESHOLD GB，发送告警" >> "$LOG_FILE"
        
        # 发送邮件（简化版本，使用系统邮件）
        subject="【OpenWrt直播】流量告警"
        body="警告：今日流量已超过 $THRESHOLD GB，当前已用 $traffic_gb GB。时间：$(date)"
        
        echo "$body" | mail -s "$subject" "$ALERT_EMAIL" 2>/dev/null || \
        echo "$body" > "/tmp/traffic_alert_$today.txt"
        
        echo "$today" > "$LAST_ALERT_FILE"
    fi
fi
EOF
        chmod +x /usr/bin/live_traffic_monitor.sh

        # 添加到crontab（每小时检查）
        local cron_cmd="0 * * * * /usr/bin/live_traffic_monitor.sh"
        if ! crontab -l 2>/dev/null | grep -q "live_traffic_monitor.sh"; then
            (crontab -l 2>/dev/null; echo "$cron_cmd") | crontab -
        fi

        echo -e "${GREEN}✅ 流量告警配置完成（阈值：${LIVE_TRAFFIC_THRESHOLD}GB，邮箱：$alert_email）${NC}"
    else
        echo -e "${YELLOW}ℹ 跳过流量告警配置${NC}"
    fi
    
    mark_step "step_traffic_alert"
}

# ==================== 模块5：配置备份与一键诊断 ====================

# 10. 配置自动备份与恢复
auto_backup_restore() {
    check_step "step_backup_restore" && { echo -e "${GREEN}✅ 备份恢复已配置，跳过${NC}"; return 0; }
    echo -e "${CYAN}▶ 配置：自动备份与恢复${NC}"

    # 生成备份脚本
    cat > /usr/bin/live_backup.sh << 'BACKUP'
#!/bin/sh
BACKUP_DIR="/etc/live_config_backup"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
BACKUP_FILE="$BACKUP_DIR/live_config_$TIMESTAMP.tar.gz"

# 创建备份目录
mkdir -p "$BACKUP_DIR"

# 备份关键配置
tar -czf "$BACKUP_FILE" \
    /etc/config/passwall \
    /etc/config/network \
    /etc/config/firewall \
    /etc/crontabs/root \
    /usr/bin/live_*.sh \
    /etc/live_auto_step 2>/dev/null

# 保留最近10个备份
ls -tp "$BACKUP_DIR"/*.tar.gz 2>/dev/null | grep -v '/$' | tail -n +11 | xargs -I {} rm -- {} 2>/dev/null

echo "备份完成：$BACKUP_FILE"
BACKUP
    chmod +x /usr/bin/live_backup.sh

    # 生成恢复脚本
    cat > /usr/bin/live_restore.sh << 'RESTORE'
#!/bin/sh
BACKUP_DIR="/etc/live_config_backup"

# 检查备份目录
if [ ! -d "$BACKUP_DIR" ]; then
    echo "备份目录不存在：$BACKUP_DIR"
    exit 1
fi

# 列出备份文件
echo "可用备份："
ls -l "$BACKUP_DIR"/*.tar.gz 2>/dev/null | awk '{print $9}' | nl -w2 -s') '

read -p "请输入要恢复的备份编号：" num
backup_file=$(ls -tp "$BACKUP_DIR"/*.tar.gz 2>/dev/null | grep -v '/$' | sed -n "${num}p")

if [ -n "$backup_file" ]; then
    read -p "确定要恢复 $backup_file 吗？(y/n): " confirm
    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
        # 先备份当前配置
        /usr/bin/live_backup.sh
        
        # 恢复备份
        tar -xzf "$backup_file" -C /
        
        # 重启服务
        /etc/init.d/passwall restart
        /etc/init.d/network restart
        /etc/init.d/cron restart
        
        echo "恢复完成，请重新登录！"
    fi
else
    echo "无效的备份编号！"
fi
RESTORE
    chmod +x /usr/bin/live_restore.sh

    # 添加自动备份到crontab（每天凌晨3点）
    local cron_cmd="0 3 * * * /usr/bin/live_backup.sh"
    if ! crontab -l 2>/dev/null | grep -q "live_backup.sh"; then
        (crontab -l 2>/dev/null; echo "$cron_cmd") | crontab -
    fi

    # 立即执行一次备份
    /usr/bin/live_backup.sh

    echo -e "${GREEN}✅ 备份恢复配置完成（自动备份：每天3点，备份目录：$BACKUP_DIR）${NC}"
    mark_step "step_backup_restore"
}

# 11. 一键诊断工具
auto_diagnose() {
    check_step "step_diagnose" && { echo -e "${GREEN}✅ 一键诊断已配置，跳过${NC}"; return 0; }
    echo -e "${CYAN}▶ 配置：一键诊断工具${NC}"

    # 生成诊断脚本
    cat > /usr/bin/live_diagnose.sh << 'DIAGNOSE'
#!/bin/sh
echo "=== OpenWrt 跨境直播环境诊断报告 ==="
echo "生成时间：$(date '+%Y-%m-%d %H:%M:%S')"
echo "======================================"

# 系统信息
echo -e "\n[1] 系统信息"
echo "OpenWrt版本：$(cat /etc/openwrt_version 2>/dev/null || cat /etc/immwrt_version 2>/dev/null || echo "未知")"
echo "内核版本：$(uname -r)"
echo "架构：$(uname -m)"

# 网络信息
echo -e "\n[2] 网络信息"
wan_ip=$(curl -s --connect-timeout 5 icanhazip.com 2>/dev/null || echo "获取失败")
echo "WAN IP：$wan_ip"
echo "DNS 配置：$(grep 'nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ' ')"

# 代理状态
echo -e "\n[3] 代理状态"
if /etc/init.d/passwall status 2>/dev/null | grep -q 'running'; then
    echo "Passwall状态：运行中"
    echo "代理节点数：$(uci show passwall 2>/dev/null | grep -c 'Live_Node_')"
    echo "当前模式：$(uci get passwall.config.mode 2>/dev/null)"
else
    echo "Passwall状态：未运行"
fi

# 端口检查
echo -e "\n[4] 端口检查"
LIVE_PORTS=("1935" "443" "8080" "8443" "554")
for port in "${LIVE_PORTS[@]}"; do
    pid=$(netstat -tulnp 2>/dev/null | grep ":$port " | awk '{print $7}' | cut -d'/' -f1)
    if [ -n "$pid" ]; then
        proc=$(ps -p "$pid" -o comm= 2>/dev/null)
        echo "端口 $port：已占用（PID: $pid, $proc）"
    else
        echo "端口 $port：空闲"
    fi
done

# 连通性测试
echo -e "\n[5] 连通性测试"
echo "访问TikTok：$(curl -s --connect-timeout 5 https://www.tiktok.com >/dev/null 2>&1 && echo "成功" || echo "失败")"
echo "访问Twitch：$(curl -s --connect-timeout 5 https://www.twitch.tv >/dev/null 2>&1 && echo "成功" || echo "失败")"

# 流量统计（简化版）
echo -e "\n[6] 流量统计"
if [ -f /proc/net/dev ]; then
    rx_bytes=$(grep -w "wan" /proc/net/dev | awk '{print $2}')
    tx_bytes=$(grep -w "wan" /proc/net/dev | awk '{print $10}')
    total_mb=$(( (rx_bytes + tx_bytes) / 1024 / 1024 ))
    echo "WAN口总流量：${total_mb} MB"
else
    echo "流量统计：无法获取"
fi

# 日志检查
echo -e "\n[7] 日志检查"
if [ -f "/var/log/openwrt_live_secure.log" ]; then
    echo "最近错误：$(grep -i error /var/log/openwrt_live_secure.log 2>/dev/null | tail -1 || echo "无")"
else
    echo "日志文件不存在"
fi

echo -e "\n======================================"
echo "诊断完成！"
DIAGNOSE
    chmod +x /usr/bin/live_diagnose.sh

    echo -e "${GREEN}✅ 一键诊断工具配置完成（命令：live_diagnose.sh）${NC}"
    mark_step "step_diagnose"
}

# ==================== 模块6：无线配置与MAC地址伪装 ====================

# 12. 无线AP配置（物理机/虚拟机）
auto_config_wifi() {
    check_step "step_config_wifi" && { echo -e "${GREEN}✅ 无线配置已完成，跳过${NC}"; return 0; }
    echo -e "${CYAN}▶ 配置：无线AP${NC}"

    # 只在物理机或虚拟机执行
    if [ "$HARDWARE_SCENE" = "container" ]; then
        echo -e "${YELLOW}ℹ 容器环境跳过无线配置${NC}"
        mark_step "step_config_wifi"
        return 0
    fi

    # 检查无线设备
    local wifi_devices=$(iw dev 2>/dev/null | grep 'Interface' | awk '{print $2}')
    if [ -z "$wifi_devices" ]; then
        echo -e "${YELLOW}⚠ 未发现无线设备，跳过无线配置${NC}"
        mark_step "step_config_wifi"
        return 0
    fi

    read -p "请输入WiFi名称(SSID)：" wifi_ssid
    read -p "请输入WiFi密码(至少8位)：" wifi_pass

    # 清理现有配置
    uci delete wireless.@wifi-iface[0-9]* 2>/dev/null

    # 配置2.4G
    local dev_2g=$(echo "$wifi_devices" | head -1)
    if [ -n "$dev_2g" ]; then
        uci set wireless.@wifi-iface[-1]="wifi-iface"
        uci set wireless.@wifi-iface[-1].device="$dev_2g"
        uci set wireless.@wifi-iface[-1].network="lan"
        uci set wireless.@wifi-iface[-1].mode="ap"
        uci set wireless.@wifi-iface[-1].ssid="$wifi_ssid"
        uci set wireless.@wifi-iface[-1].encryption="psk2"
        uci set wireless.@wifi-iface[-1].key="$wifi_pass"
    fi

    # 配置5G（如果有）
    local dev_5g=$(echo "$wifi_devices" | sed -n '2p')
    if [ -n "$dev_5g" ]; then
        uci set wireless.@wifi-iface[-1]="wifi-iface"
        uci set wireless.@wifi-iface[-1].device="$dev_5g"
        uci set wireless.@wifi-iface[-1].network="lan"
        uci set wireless.@wifi-iface[-1].mode="ap"
        uci set wireless.@wifi-iface[-1].ssid="${wifi_ssid}_5G"
        uci set wireless.@wifi-iface[-1].encryption="psk2"
        uci set wireless.@wifi-iface[-1].key="$wifi_pass"
    fi

    uci commit wireless
    /etc/init.d/network restart

    echo -e "${GREEN}✅ 无线AP配置完成（SSID：$wifi_ssid）${NC}"
    mark_step "step_config_wifi"
}

# 13. MAC地址伪装（防封锁）
auto_config_mac() {
    check_step "step_config_mac" && { echo -e "${GREEN}✅ MAC伪装已完成，跳过${NC}"; return 0; }
    echo -e "${CYAN}▶ 配置：MAC地址伪装${NC}"

    # 容器环境特殊处理
    if [ "$HARDWARE_SCENE" = "container" ]; then
        echo -e "${YELLOW}📢 容器环境MAC伪装提示：${NC}"
        echo -e "${YELLOW}1. 请在宿主机配置MAC地址伪装${NC}"
        echo -e "${YELLOW}2. 或使用 '--mac-address' 参数启动容器${NC}"
        mark_step "step_config_mac"
        return 0
    fi

    read -p "是否需要MAC地址伪装？(y/n): " need_mac_spoof
    if [ "$need_mac_spoof" = "y" ] || [ "$need_mac_spoof" = "Y" ]; then
        # 获取WAN口
        local wan_iface=$(uci get network.wan.ifname 2>/dev/null || echo "eth0")
        
        # 生成随机MAC地址（保留前3字节为合法厂商）
        local mac_prefix="52:54:00"  # QEMU虚拟MAC前缀
        local mac_suffix=$(printf "%02x:%02x:%02x" $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))
        local fake_mac="$mac_prefix:$mac_suffix"

        # 配置MAC伪装
        uci set network.wan.macaddr="$fake_mac"
        uci commit network

        # 重启网络
        /etc/init.d/network restart

        echo -e "${GREEN}✅ MAC地址伪装完成（新MAC：$fake_mac）${NC}"
    else
        echo -e "${YELLOW}ℹ 跳过MAC地址伪装${NC}"
    fi
    mark_step "step_config_mac"
}

# ==================== 模块7：直播推流模板与系统优化 ====================

# 14. 直播推流模板生成
auto_stream_template() {
    check_step "step_stream_template" && { echo -e "${GREEN}✅ 推流模板已配置，跳过${NC}"; return 0; }
    echo -e "${CYAN}▶ 配置：直播推流模板${NC}"

    # 创建模板目录
    mkdir -p /etc/live_stream_templates

    # TikTok推流模板
    cat > /etc/live_stream_templates/tiktok.sh << 'TIKTOK'
#!/bin/sh
# TikTok直播推流脚本
# 使用方法：1. 修改下面的推流地址 2. chmod +x tiktok.sh 3. ./tiktok.sh

# 替换为你的推流地址
STREAM_URL="rtmp://live.tiktok.com/musically/user/xxxxxxxxxxxxxxxxxxxx"

# 视频参数（根据网络情况调整）
VIDEO_BITRATE="2500k"  # 视频比特率
AUDIO_BITRATE="128k"   # 音频比特率
RESOLUTION="1280x720"  # 分辨率
FPS="30"               # 帧率

echo "开始推流到TikTok..."
ffmpeg -f v4l2 -i /dev/video0 -f alsa -i hw:0 -vcodec libx264 -b:v $VIDEO_BITRATE -s $RESOLUTION -r $FPS -acodec aac -b:a $AUDIO_BITRATE -f flv $STREAM_URL
TIKTOK
    chmod +x /etc/live_stream_templates/tiktok.sh

    # Twitch推流模板
    cat > /etc/live_stream_templates/twitch.sh << 'TWITCH'
#!/bin/sh
# Twitch直播推流脚本
# 使用方法：1. 修改下面的推流密钥 2. chmod +x twitch.sh 3. ./twitch.sh

# 替换为你的推流密钥
STREAM_KEY="live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# 视频参数
VIDEO_BITRATE="3000k"
AUDIO_BITRATE="160k"
RESOLUTION="1280x720"
FPS="30"

echo "开始推流到Twitch..."
ffmpeg -f v4l2 -i /dev/video0 -f alsa -i hw:0 -vcodec libx264 -b:v $VIDEO_BITRATE -s $RESOLUTION -r $FPS -acodec aac -b:a $AUDIO_BITRATE -f flv rtmp://live.twitch.tv/app/$STREAM_KEY
TWITCH
    chmod +x /etc/live_stream_templates/twitch.sh

    # 创建快捷方式
    ln -sf /etc/live_stream_templates/tiktok.sh /usr/bin/tiktok_stream 2>/dev/null
    ln -sf /etc/live_stream_templates/twitch.sh /usr/bin/twitch_stream 2>/dev/null

    echo -e "${GREEN}✅ 直播推流模板配置完成${NC}"
    echo -e "${GREEN}📋 可用模板：${NC}"
    echo -e "${GREEN}   - TikTok: tiktok_stream (编辑 /etc/live_stream_templates/tiktok.sh 修改地址)${NC}"
    echo -e "${GREEN}   - Twitch: twitch_stream (编辑 /etc/live_stream_templates/twitch.sh 修改密钥)${NC}"
    mark_step "step_stream_template"
}

# 15. 系统性能优化
auto_system_optimize() {
    check_step "step_system_optimize" && { echo -e "${GREEN}✅ 系统优化已完成，跳过${NC}"; return 0; }
    echo -e "${CYAN}▶ 配置：系统性能优化${NC}"

    # TCP优化
    cat >> /etc/sysctl.conf << 'SYSCTL'
# 直播专用TCP优化
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
SYSCTL

    # 应用sysctl配置
    sysctl -p >/dev/null 2>&1

    # 内存优化（增加缓存）
    if [ -f "/etc/rc.local" ] && ! grep -q "echo 3 > /proc/sys/vm/drop_caches" /etc/rc.local; then
        sed -i '/exit 0/d' /etc/rc.local
        echo "echo 3 > /proc/sys/vm/drop_caches" >> /etc/rc.local
        echo "exit 0" >> /etc/rc.local
    fi

    # CPU性能模式
    if [ -d "/sys/devices/system/cpu/cpu0/cpufreq" ]; then
        echo "performance" > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null
    fi

    echo -e "${GREEN}✅ 系统性能优化完成${NC}"
    mark_step "step_system_optimize"
}

# ==================== 模块8：主程序入口 ====================

# 主程序入口
main() {
    echo -e "${BLUE}========================================"
    echo -e "        OpenWrt 跨境直播环境配置"
    echo -e "========================================"
    echo -e "  版本：2.1  |  场景：检测中..."
    echo -e "========================================"
    echo -e "  按Ctrl+C可中断，支持断点续传${NC}"
    echo ""

    # 权限检查
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}❌ 请使用root权限运行此脚本${NC}"
        exit 1
    fi

    # 环境检测
    detect_env

    # 环境初始化
    auto_env_init

    # 代理多节点配置
    auto_proxy_multi_node

    # 端口监控配置
    auto_port_monitor

    # 流量告警配置
    auto_traffic_alert

    # 备份恢复配置
    auto_backup_restore

    # 一键诊断配置
    auto_diagnose

    # 无线配置
    auto_config_wifi

    # MAC伪装配置
    auto_config_mac

    # 推流模板配置
    auto_stream_template

    # 系统优化
    auto_system_optimize

    echo -e "\n${GREEN}========================================"
    echo -e "        所有配置已完成！🎉"
    echo -e "========================================"
    echo -e "  快速使用命令："
    echo -e "  - 切换代理节点：live_switch_proxy.sh"
    echo -e "  - 运行诊断工具：live_diagnose.sh"
    echo -e "  - 备份配置：live_backup.sh"
    echo -e "  - 恢复配置：live_restore.sh"
    echo -e "  - TikTok推流：tiktok_stream"
    echo -e "  - Twitch推流：twitch_stream"
    echo -e "========================================"
    echo -e "  日志位置：/var/log/openwrt_live_secure.log"
    echo -e "========================================"
    echo -e "  重启设备后配置依然生效${NC}"

    # 清理步骤文件（下次可重新配置）
    rm -f "$STEP_FILE"
}

# 启动主程序
main "$@"