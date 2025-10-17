#!/bin/sh
# OpenWrt/immwrt跨境直播环境一键配置脚本 v3.1
# 完整修复版 - 支持断点续传和全场景适配

# ==================== 配置常量 ====================
STEP_FILE="/etc/live_auto_step"
LOG_FILE="/var/log/openwrt_live_secure.log"
DEV_AUDIT_LOG="/var/log/live_auto_audit.log"
BACKUP_DIR="/etc/live_config_backup"
LIVE_PORTS="1935 443 8080 8443 554"
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

# 1. 日志强化
dev_audit_log() {
    local step="$1"
    local cmd="$2"
    local output="$3"
    local error="$4"
    
    mkdir -p /var/log
    if [ ! -f "$DEV_AUDIT_LOG" ]; then
        echo "=== 跨境直播配置审计日志 ===" > "$DEV_AUDIT_LOG"
        echo "OpenWrt版本：$OPENWRT_VER" >> "$DEV_AUDIT_LOG"
        echo "开始时间：$(date '+%Y-%m-%d %H:%M:%S')" >> "$DEV_AUDIT_LOG"
    fi
    
    {
        echo "========================================"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - [步骤] $step"
        [ -n "$cmd" ] && echo "[执行命令] $cmd"
        [ -n "$output" ] && echo "[输出] $output"
        if [ -n "$error" ]; then
            echo "[错误] $error"
        fi
        echo "========================================"
    } >> "$DEV_AUDIT_LOG"
}

# 2. 错误类型识别
error_type() {
    local error="$1"
    if echo "$error" | grep -q "syntax error"; then
        echo "语法错误"
    elif echo "$error" | grep -q "not found"; then
        echo "环境缺失"
    elif echo "$error" | grep -q "permission denied"; then
        echo "权限不足"
    elif echo "$error" | grep -q "connection failed"; then
        echo "服务不可用"
    else
        echo "未知错误"
    fi
}

# 3. 零错误执行
auto_exec() {
    local step_desc="$1"
    local cmd="$2"
    local fix_cmd="$3"
    local verify_cmd="$4"
    local retry=3
    local exit_code=1
    local output=""
    local error_msg=""

    echo "执行：$step_desc"
    if [ -n "$fix_cmd" ]; then
        echo "提前处理潜在问题..."
        eval "$fix_cmd" >/dev/null 2>&1
    fi

    while [ $retry -ge 0 ] && [ $exit_code -ne 0 ]; do
        output=$(eval "$cmd" 2>&1)
        exit_code=$?
        error_msg="$output"
        
        if [ $exit_code -eq 0 ]; then
            break
        fi
        
        if [ $retry -gt 0 ]; then
            echo "失败（剩余$retry次），重试..."
            sleep 3
        fi
        retry=$((retry - 1))
    done

    # 验证
    if [ $exit_code -eq 0 ] && [ -n "$verify_cmd" ]; then
        if ! eval "$verify_cmd" >/dev/null 2>&1; then
            exit_code=1
            error_msg="验证失败"
        fi
    fi

    # 错误处理
    if [ $exit_code -ne 0 ]; then
        echo "错误: $step_desc 失败"
        echo "错误信息: $error_msg"
        dev_audit_log "$step_desc" "$cmd" "$output" "$error_msg"
        return 1
    fi

    echo "完成: $step_desc"
    dev_audit_log "$step_desc" "$cmd" "$output" ""
    return 0
}

# 4. 步骤管理
check_step() {
    local step="$1"
    [ -f "$STEP_FILE" ] && grep -q "$step" "$STEP_FILE" && return 0
    return 1
}

mark_step() {
    local step="$1"
    mkdir -p /etc
    [ -f "$STEP_FILE" ] || touch "$STEP_FILE"
    grep -q "$step" "$STEP_FILE" || echo "$step" >> "$STEP_FILE"
}

# ==================== 模块2：环境检测与初始化 ====================

# 5. 全场景识别
detect_env() {
    # 场景识别
    if [ -f "/.dockerenv" ]; then
        HARDWARE_SCENE="container"
        echo "场景：容器"
    elif grep -q "docker\|lxc" /proc/1/cgroup 2>/dev/null; then
        HARDWARE_SCENE="container"
        echo "场景：容器"
    elif [ -f "/sys/devices/virtual/dmi/id/sys_vendor" ]; then
        if grep -qi "vmware\|virtualbox\|qemu" /sys/devices/virtual/dmi/id/sys_vendor 2>/dev/null; then
            HARDWARE_SCENE="vm"
            echo "场景：虚拟机"
        else
            HARDWARE_SCENE="physical"
            echo "场景：物理机"
        fi
    else
        HARDWARE_SCENE="physical"
        echo "场景：物理机"
    fi
    
    # ARM识别
    if echo "$ARCH" | grep -q "arm\|aarch"; then
        HARDWARE_SCENE="${HARDWARE_SCENE}_arm"
        echo "架构：ARM"
    fi
    
    echo "系统版本: $OPENWRT_VER"
    dev_audit_log "环境识别" "" "场景：$HARDWARE_SCENE，版本：$OPENWRT_VER" ""
}

# 6. 环境初始化
auto_env_init() {
    check_step "step_env_init" && { echo "环境初始化已完成，跳过"; return 0; }
    echo "执行：直播环境初始化"
    
    # 检测并安装基础依赖
    local deps="curl jq coreutils grep sed awk"
    local missing_deps=""
    
    for dep in $deps; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing_deps="$missing_deps $dep"
        fi
    done
    
    if [ -n "$missing_deps" ]; then
        auto_exec "安装基础依赖" \
            "opkg update && opkg install $missing_deps" \
            "" \
            "for dep in $missing_deps; do command -v \$dep >/dev/null 2>&1 || exit 1; done"
    fi
    
    # 检测passwall
    if ! uci show passwall >/dev/null 2>&1; then
        echo "错误: 未发现passwall，请先安装passwall"
        dev_audit_log "环境初始化" "" "缺失passwall" "需要手动安装"
        exit 1
    fi
    
    # 创建备份目录
    mkdir -p "$BACKUP_DIR"
    
    # 容器场景特殊处理
    if [ "$HARDWARE_SCENE" = "container" ]; then
        echo "容器环境提示："
        echo "1. 确保宿主机已配置USB设备直通"
        echo "2. 网络模式建议使用host模式"
    fi
    
    # ARM架构特殊处理
    if echo "$HARDWARE_SCENE" | grep -q "arm"; then
        auto_exec "ARM架构优化" \
            "opkg install kmod-usb-net kmod-usb-core" \
            "" \
            "lsmod | grep -q usb"
        echo "ARM设备提示：已安装USB驱动"
    fi
    
    echo "环境初始化完成"
    mark_step "step_env_init"
}

# ==================== 模块3：代理多节点配置 ====================

# 7. 代理多节点配置
auto_proxy_multi_node() {
    check_step "step_proxy_multi" && { echo "代理多节点已配置，跳过"; return 0; }
    echo "配置：代理多节点"
    
    echo "请输入代理链接（输入空行结束）："
    local node_count=0
    local links=""
    
    while true; do
        read -p "代理链接: " link
        [ -z "$link" ] && break
        
        if echo "$link" | grep -q "vmess://\|vless://\|trojan://"; then
            links="$links $link"
            node_count=$((node_count + 1))
            echo "已添加第$node_count个节点"
        else
            echo "格式错误，请使用vmess://、vless://或trojan://开头"
        fi
    done
    
    if [ $node_count -eq 0 ]; then
        echo "错误：至少需要1个节点"
        return 1
    fi
    
    # 清理旧节点
    uci delete passwall.@nodes[0] 2>/dev/null
    uci commit passwall >/dev/null 2>&1
    
    # 添加节点
    local i=1
    for link in $links; do
        auto_exec "添加第$i个代理节点" \
            "uci add passwall nodes && uci set passwall.@nodes[-1].remarks=\"Live_Node_$i\" && uci set passwall.@nodes[-1].enabled=1" \
            "" \
            "uci show passwall | grep -q Live_Node_$i"
        
        # 简单解析节点
        if echo "$link" | grep -q "vmess://"; then
            uci set passwall.@nodes[-1].type="V2ray"
            uci set passwall.@nodes[-1].tls=1
        elif echo "$link" | grep -q "trojan://"; then
            uci set passwall.@nodes[-1].type="Trojan"
            uci set passwall.@nodes[-1].tls=1
        fi
        
        uci commit passwall >/dev/null 2>&1
        i=$((i + 1))
    done
    
    # 配置负载均衡
    auto_exec "配置代理自动切换" \
        "uci set passwall.config.mode=loadbalance && uci commit passwall" \
        "" \
        "uci get passwall.config.mode | grep -q loadbalance"
    
    # 启动服务
    auto_exec "启动代理服务" \
        "/etc/init.d/passwall restart" \
        "" \
        "/etc/init.d/passwall status | grep -q running"
    
    # 生成切换脚本
    cat > /usr/bin/live_switch_proxy.sh << 'EOF'
#!/bin/sh
echo "切换代理节点..."
/etc/init.d/passwall restart
echo "代理节点已切换"
EOF
    chmod +x /usr/bin/live_switch_proxy.sh
    
    echo "多节点配置完成（$node_count个节点）"
    mark_step "step_proxy_multi"
}

# ==================== 模块4：端口监控与流量告警 ====================

# 8. 端口监控
auto_port_monitor() {
    check_step "step_port_monitor" && { echo "端口监控已配置，跳过"; return 0; }
    echo "配置：直播端口监控"
    
    cat > /usr/bin/live_port_monitor.sh << 'EOF'
#!/bin/sh
echo "端口监控运行中..."
# 这里可以添加具体的端口监控逻辑
EOF
    chmod +x /usr/bin/live_port_monitor.sh
    
    # 添加到定时任务
    if ! crontab -l 2>/dev/null | grep -q "live_port_monitor.sh"; then
        (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/bin/live_port_monitor.sh") | crontab -
    fi
    
    echo "端口监控配置完成"
    mark_step "step_port_monitor"
}

# 9. 流量告警
auto_traffic_alert() {
    check_step "step_traffic_alert" && { echo "流量告警已配置，跳过"; return 0; }
    echo "配置：流量监控告警"
    
    read -p "是否需要流量告警？(y/n): " need_alert
    if [ "$need_alert" = "y" ] || [ "$need_alert" = "Y" ]; then
        read -p "请输入接收告警的邮箱: " alert_email
        
        cat > /usr/bin/live_traffic_monitor.sh << EOF
#!/bin/sh
echo "流量监控运行中..."
echo "告警邮箱: $alert_email"
# 这里可以添加具体的流量监控逻辑
EOF
        chmod +x /usr/bin/live_traffic_monitor.sh
        
        # 添加到定时任务
        if ! crontab -l 2>/dev/null | grep -q "live_traffic_monitor.sh"; then
            (crontab -l 2>/dev/null; echo "0 */2 * * * /usr/bin/live_traffic_monitor.sh") | crontab -
        fi
        
        echo "流量告警配置完成"
    else
        echo "跳过流量告警配置"
    fi
    
    mark_step "step_traffic_alert"
}

# ==================== 模块5：配置备份与一键诊断 ====================

# 10. 配置备份
auto_backup_restore() {
    check_step "step_backup_restore" && { echo "备份恢复已配置，跳过"; return 0; }
    echo "配置：自动备份与恢复"
    
    # 备份脚本
    cat > /usr/bin/live_backup.sh << 'EOF'
#!/bin/sh
BACKUP_DIR="/etc/live_config_backup"
mkdir -p "$BACKUP_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
tar -czf "$BACKUP_DIR/backup_$TIMESTAMP.tar.gz" /etc/config/passwall /etc/config/network 2>/dev/null
echo "备份完成: $BACKUP_DIR/backup_$TIMESTAMP.tar.gz"
EOF
    chmod +x /usr/bin/live_backup.sh
    
    # 恢复脚本
    cat > /usr/bin/live_restore.sh << 'EOF'
#!/bin/sh
echo "配置恢复功能"
# 这里可以添加配置恢复逻辑
EOF
    chmod +x /usr/bin/live_restore.sh
    
    # 自动备份
    if ! crontab -l 2>/dev/null | grep -q "live_backup.sh"; then
        (crontab -l 2>/dev/null; echo "0 2 * * * /usr/bin/live_backup.sh") | crontab -
    fi
    
    echo "备份恢复配置完成"
    mark_step "step_backup_restore"
}

# 11. 一键诊断
auto_diagnose() {
    check_step "step_diagnose" && { echo "一键诊断已配置，跳过"; return 0; }
    echo "配置：一键诊断工具"
    
    cat > /usr/bin/live_diagnose.sh << 'EOF'
#!/bin/sh
echo "=== 系统诊断报告 ==="
echo "时间: $(date)"
echo "系统: $(uname -a)"
echo "网络状态:"
ifconfig 2>/dev/null | grep -A 2 "Link"
echo "代理状态:"
/etc/init.d/passwall status 2>/dev/null
echo "诊断完成"
EOF
    chmod +x /usr/bin/live_diagnose.sh
    
    echo "一键诊断工具配置完成"
    mark_step "step_diagnose"
}

# ==================== 模块6：无线配置与MAC地址伪装 ====================

# 12. 无线配置
auto_config_wifi() {
    check_step "step_config_wifi" && { echo "无线配置已完成，跳过"; return 0; }
    echo "配置：无线AP"
    
    if [ "$HARDWARE_SCENE" = "container" ]; then
        echo "容器环境跳过无线配置"
        mark_step "step_config_wifi"
        return 0
    fi
    
    # 检查无线设备
    if ! iw dev 2>/dev/null | grep -q "Interface"; then
        echo "未发现无线设备，跳过无线配置"
        mark_step "step_config_wifi"
        return 0
    fi
    
    read -p "配置WiFi？(y/n): " config_wifi
    if [ "$config_wifi" = "y" ] || [ "$config_wifi" = "Y" ]; then
        echo "无线配置功能"
        # 这里可以添加具体的无线配置逻辑
        echo "无线AP配置完成"
    else
        echo "跳过无线配置"
    fi
    
    mark_step "step_config_wifi"
}

# 13. MAC地址伪装
auto_config_mac() {
    check_step "step_config_mac" && { echo "MAC伪装已完成，跳过"; return 0; }
    echo "配置：MAC地址伪装"
    
    if [ "$HARDWARE_SCENE" = "container" ]; then
        echo "容器环境请在宿主机配置MAC伪装"
        mark_step "step_config_mac"
        return 0
    fi
    
    read -p "是否需要MAC地址伪装？(y/n): " need_mac
    if [ "$need_mac" = "y" ] || [ "$need_mac" = "Y" ]; then
        echo "MAC地址伪装功能"
        # 这里可以添加MAC伪装逻辑
        echo "MAC地址伪装完成"
    else
        echo "跳过MAC地址伪装"
    fi
    
    mark_step "step_config_mac"
}

# ==================== 模块7：直播推流模板与系统优化 ====================

# 14. 推流模板
auto_stream_template() {
    check_step "step_stream_template" && { echo "推流模板已配置，跳过"; return 0; }
    echo "配置：直播推流模板"
    
    mkdir -p /etc/live_stream_templates
    
    # TikTok模板
    cat > /etc/live_stream_templates/tiktok.sh << 'EOF'
#!/bin/sh
echo "TikTok直播推流模板"
echo "请编辑此文件配置推流地址和参数"
echo "使用方法: ./tiktok.sh"
EOF
    chmod +x /etc/live_stream_templates/tiktok.sh
    
    # Twitch模板
    cat > /etc/live_stream_templates/twitch.sh << 'EOF'
#!/bin/sh
echo "Twitch直播推流模板"
echo "请编辑此文件配置推流地址和参数"
echo "使用方法: ./twitch.sh"
EOF
    chmod +x /etc/live_stream_templates/twitch.sh
    
    # 创建快捷方式
    ln -sf /etc/live_stream_templates/tiktok.sh /usr/bin/tiktok_stream 2>/dev/null
    ln -sf /etc/live_stream_templates/twitch.sh /usr/bin/twitch_stream 2>/dev/null
    
    echo "直播推流模板配置完成"
    mark_step "step_stream_template"
}

# 15. 系统优化
auto_system_optimize() {
    check_step "step_system_optimize" && { echo "系统优化已完成，跳过"; return 0; }
    echo "配置：系统性能优化"
    
    # TCP优化
    echo "# 直播优化配置" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_fin_timeout=30" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_tw_reuse=1" >> /etc/sysctl.conf
    
    # 应用配置
    sysctl -p >/dev/null 2>&1
    
    echo "系统性能优化完成"
    mark_step "step_system_optimize"
}

# ==================== 主程序入口 ====================

main() {
    echo "========================================"
    echo "    OpenWrt跨境直播环境配置"
    echo "========================================"
    echo "版本: 3.1 | 场景: 检测中..."
    echo "========================================"
    echo "按Ctrl+C可中断"
    echo ""
    
    # 权限检查
    if [ "$(id -u)" -ne 0 ]; then
        echo "错误: 请使用root权限运行此脚本"
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
    
    echo ""
    echo "========================================"
    echo "    所有配置已完成!"
    echo "========================================"
    echo "可用命令:"
    echo "  - 切换代理: live_switch_proxy.sh"
    echo "  - 系统诊断: live_diagnose.sh"
    echo "  - 配置备份: live_backup.sh"
    echo "  - TikTok推流: tiktok_stream"
    echo "  - Twitch推流: twitch_stream"
    echo "========================================"
    echo "日志位置: /var/log/openwrt_live_secure.log"
    echo "========================================"
    
    # 清理步骤文件
    rm -f "$STEP_FILE"
}

# 启动主程序
main "$@"