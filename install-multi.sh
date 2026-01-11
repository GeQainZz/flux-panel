#!/bin/bash
set -e

# =======================
# 基础配置
# =======================
BASE_DIR="/etc/gost"
DOWNLOAD_URL="https://github.com/bqlpfy/flux-panel/releases/download/1.4.2/gost"

# CN 镜像（带超时与容错）
COUNTRY="$(curl -s --max-time 3 https://ipinfo.io/country 2>/dev/null || true)"
COUNTRY="$(echo "$COUNTRY" | tr -d '\r\n ')"
if [ "$COUNTRY" = "CN" ]; then
  DOWNLOAD_URL="https://ghfast.top/${DOWNLOAD_URL}"
fi

# sudo 处理
if [[ $EUID -ne 0 ]]; then
  SUDO_CMD="sudo"
else
  SUDO_CMD=""
fi

# =======================
# 显示菜单
# =======================
show_menu() {
  echo "==============================================="
  echo "              GOST 多实例管理脚本"
  echo "==============================================="
  echo "当前下载地址: $DOWNLOAD_URL"
  echo "基础目录: $BASE_DIR"
  echo "请选择操作："
  echo "1. 安装（指定实例）"
  echo "2. 更新（指定实例）"
  echo "3. 卸载（指定实例）"
  echo "4. 查看实例状态（status）"
  echo "5. 列出已安装实例（list）"
  echo "6. 退出"
  echo "==============================================="
}

# 删除脚本自身（保留你的习惯）
delete_self() {
  echo ""
  echo "🗑️ 操作已完成，正在清理脚本文件..."
  SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")"
  sleep 1
  rm -f "$SCRIPT_PATH" && echo "✅ 脚本文件已删除" || echo "❌ 删除脚本文件失败"
}

# =======================
# tcpkill / dsniff 安装
# =======================
check_and_install_tcpkill() {
  if command -v tcpkill &>/dev/null; then
    return 0
  fi

  OS_TYPE="$(uname -s)"

  if [[ "$OS_TYPE" == "Darwin" ]]; then
    if command -v brew &>/dev/null; then
      brew install dsniff &>/dev/null || true
    fi
    return 0
  fi

  local DISTRO=""
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
  elif [ -f /etc/redhat-release ]; then
    DISTRO="rhel"
  elif [ -f /etc/debian_version ]; then
    DISTRO="debian"
  else
    return 0
  fi

  case $DISTRO in
    ubuntu|debian)
      $SUDO_CMD apt update -y &>/dev/null || true
      $SUDO_CMD apt install -y dsniff &>/dev/null || true
      ;;
    centos|rhel|fedora)
      if command -v dnf &>/dev/null; then
        $SUDO_CMD dnf install -y dsniff &>/dev/null || true
      elif command -v yum &>/dev/null; then
        $SUDO_CMD yum install -y dsniff &>/dev/null || true
      fi
      ;;
    alpine)
      $SUDO_CMD apk add --no-cache dsniff &>/dev/null || true
      ;;
    arch|manjaro)
      $SUDO_CMD pacman -S --noconfirm dsniff &>/dev/null || true
      ;;
    opensuse*|sles)
      $SUDO_CMD zypper install -y dsniff &>/dev/null || true
      ;;
    gentoo)
      $SUDO_CMD emerge --ask=n net-analyzer/dsniff &>/dev/null || true
      ;;
    void)
      $SUDO_CMD xbps-install -Sy dsniff &>/dev/null || true
      ;;
  esac

  return 0
}

# =======================
# 参数与实例处理
# =======================
INSTANCE_NAME=""
SERVER_ADDR=""
SECRET=""

usage() {
  echo "用法："
  echo "  $0 -i <实例名> -a <服务器地址> -s <密钥>"
  echo "示例："
  echo "  $0 -i master-a -a 1.2.3.4:1234 -s keyA"
}

# 解析命令行参数：-i 实例名 -a 地址 -s 密钥
while getopts "i:a:s:" opt; do
  case $opt in
    i) INSTANCE_NAME="$OPTARG" ;;
    a) SERVER_ADDR="$OPTARG" ;;
    s) SECRET="$OPTARG" ;;
    *) echo "❌ 无效参数"; usage; exit 1 ;;
  esac
done

get_instance_name() {
  if [[ -z "$INSTANCE_NAME" ]]; then
    read -p "实例名称（如 master-a）: " INSTANCE_NAME
  fi
  if [[ ! "$INSTANCE_NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "❌ 实例名称不合法，只允许字母/数字/_/-"
    exit 1
  fi
}

get_config_params() {
  if [[ -z "$SERVER_ADDR" || -z "$SECRET" ]]; then
    echo "请输入配置参数："
    [[ -z "$SERVER_ADDR" ]] && read -p "服务器地址: " SERVER_ADDR
    [[ -z "$SECRET" ]] && read -p "密钥: " SECRET
  fi

  if [[ -z "$SERVER_ADDR" || -z "$SECRET" ]]; then
    echo "❌ 参数不完整，操作取消。"
    exit 1
  fi
}

set_instance_paths() {
  INSTALL_DIR="${BASE_DIR}/${INSTANCE_NAME}"
  SERVICE_NAME="gost-${INSTANCE_NAME}"
  SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
  CONFIG_FILE="${INSTALL_DIR}/config.json"
  GOST_CONFIG="${INSTALL_DIR}/gost.json"
}

require_systemd() {
  command -v systemctl &>/dev/null || {
    echo "❌ 未检测到 systemd(systemctl)，无法创建/管理服务。"
    exit 1
  }
}

# =======================
# 安装
# =======================
install_gost() {
  echo "🚀 开始安装 GOST（多实例）..."
  require_systemd
  get_instance_name
  set_instance_paths
  get_config_params

  check_and_install_tcpkill

  echo "📁 实例目录: $INSTALL_DIR"
  echo "🧩 服务名称: $SERVICE_NAME"

  $SUDO_CMD mkdir -p "$INSTALL_DIR"

  if [[ -f "$SERVICE_FILE" ]]; then
    echo "🔍 检测到已存在服务: $SERVICE_NAME（将覆盖该实例）"
    $SUDO_CMD systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    $SUDO_CMD systemctl disable "$SERVICE_NAME" 2>/dev/null || true
  fi

  echo "⬇️ 下载 gost 中..."
  $SUDO_CMD curl -fL --connect-timeout 5 --max-time 60 "$DOWNLOAD_URL" -o "$INSTALL_DIR/gost"
  if [[ ! -f "$INSTALL_DIR/gost" || ! -s "$INSTALL_DIR/gost" ]]; then
    echo "❌ 下载失败，请检查网络或下载链接。"
    exit 1
  fi
  $SUDO_CMD chmod +x "$INSTALL_DIR/gost"
  echo "✅ 下载完成"
  echo "🔎 gost 版本：$($INSTALL_DIR/gost -V 2>/dev/null || echo 'unknown')"

  echo "📄 写入配置: $CONFIG_FILE"
  $SUDO_CMD tee "$CONFIG_FILE" >/dev/null <<EOF
{
  "addr": "$SERVER_ADDR",
  "secret": "$SECRET"
}
EOF

  if [[ -f "$GOST_CONFIG" ]]; then
    echo "⏭️ 跳过配置文件: $GOST_CONFIG (已存在)"
  else
    echo "📄 创建新配置: $GOST_CONFIG"
    $SUDO_CMD tee "$GOST_CONFIG" >/dev/null <<EOF
{}
EOF
  fi

  $SUDO_CMD chmod 600 "$INSTALL_DIR"/*.json 2>/dev/null || true

  echo "🧷 创建服务文件: $SERVICE_FILE"
  $SUDO_CMD tee "$SERVICE_FILE" >/dev/null <<EOF
[Unit]
Description=Gost Proxy Service (${INSTANCE_NAME})
After=network.target

[Service]
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/gost
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

  $SUDO_CMD systemctl daemon-reload
  $SUDO_CMD systemctl enable "$SERVICE_NAME"
  $SUDO_CMD systemctl start "$SERVICE_NAME"

  echo "🔄 检查服务状态..."
  if $SUDO_CMD systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "✅ 安装完成：$SERVICE_NAME 已启动并设置为开机启动。"
    echo "📁 配置目录: $INSTALL_DIR"
    echo "🔧 服务状态: $($SUDO_CMD systemctl is-active "$SERVICE_NAME")"
  else
    echo "❌ 服务启动失败，请查看日志："
    echo "journalctl -u $SERVICE_NAME -f"
    exit 1
  fi
}

# =======================
# 更新（只更新指定实例）
# =======================
update_gost() {
  echo "🔄 开始更新 GOST（指定实例）..."
  require_systemd
  get_instance_name
  set_instance_paths

  if [[ ! -d "$INSTALL_DIR" ]]; then
    echo "❌ 该实例未安装：$INSTANCE_NAME"
    echo "   目录不存在：$INSTALL_DIR"
    return 1
  fi

  echo "📥 使用下载地址: $DOWNLOAD_URL"
  check_and_install_tcpkill

  echo "⬇️ 下载新版本..."
  $SUDO_CMD curl -fL --connect-timeout 5 --max-time 60 "$DOWNLOAD_URL" -o "$INSTALL_DIR/gost.new"
  if [[ ! -f "$INSTALL_DIR/gost.new" || ! -s "$INSTALL_DIR/gost.new" ]]; then
    echo "❌ 下载失败。"
    return 1
  fi

  echo "🛑 停止服务: $SERVICE_NAME"
  $SUDO_CMD systemctl stop "$SERVICE_NAME" 2>/dev/null || true

  echo "🔁 替换二进制..."
  $SUDO_CMD mv "$INSTALL_DIR/gost.new" "$INSTALL_DIR/gost"
  $SUDO_CMD chmod +x "$INSTALL_DIR/gost"

  echo "🔎 新版本：$($INSTALL_DIR/gost -V 2>/dev/null || echo 'unknown')"

  echo "▶️ 启动服务..."
  $SUDO_CMD systemctl start "$SERVICE_NAME"

  echo "✅ 更新完成：$SERVICE_NAME 已重新启动。"
}

# =======================
# 卸载（只卸载指定实例）
# =======================
uninstall_gost() {
  echo "🗑️ 开始卸载 GOST（指定实例）..."
  require_systemd
  get_instance_name
  set_instance_paths

  read -p "确认卸载实例 [$INSTANCE_NAME] 吗？将删除该实例所有文件 (y/N): " confirm
  if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "❌ 取消卸载"
    return 0
  fi

  echo "🛑 停止并禁用服务: $SERVICE_NAME"
  $SUDO_CMD systemctl stop "$SERVICE_NAME" 2>/dev/null || true
  $SUDO_CMD systemctl disable "$SERVICE_NAME" 2>/dev/null || true

  if [[ -f "$SERVICE_FILE" ]]; then
    $SUDO_CMD rm -f "$SERVICE_FILE"
    echo "🧹 删除服务文件: $SERVICE_FILE"
  fi

  if [[ -d "$INSTALL_DIR" ]]; then
    $SUDO_CMD rm -rf "$INSTALL_DIR"
    echo "🧹 删除实例目录: $INSTALL_DIR"
  fi

  $SUDO_CMD systemctl daemon-reload
  echo "✅ 卸载完成：实例 [$INSTANCE_NAME]"
}

# =======================
# 查看实例状态（新增）
# =======================
status_instance() {
  echo "🔎 查看实例状态..."
  require_systemd
  get_instance_name
  set_instance_paths

  if [[ ! -f "$SERVICE_FILE" ]]; then
    echo "❌ 未找到该实例服务文件：$SERVICE_FILE"
    echo "   可能未安装或实例名写错。"
    return 1
  fi

  echo "🧩 服务名称: $SERVICE_NAME"
  echo "📁 实例目录: $INSTALL_DIR"
  echo "-----------------------------------------------"
  echo "Active: $($SUDO_CMD systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo unknown)"
  echo "Enabled: $($SUDO_CMD systemctl is-enabled "$SERVICE_NAME" 2>/dev/null || echo unknown)"
  echo "-----------------------------------------------"
  echo "📌 systemctl status（按 q 退出）："
  $SUDO_CMD systemctl status "$SERVICE_NAME" --no-pager || true
  echo "-----------------------------------------------"
  echo "📌 查看实时日志：journalctl -u $SERVICE_NAME -f"
}

# =======================
# 列出已安装实例（新增）
# =======================
list_instances() {
  echo "📋 已安装实例列表（扫描：$BASE_DIR）"
  require_systemd

  if [[ ! -d "$BASE_DIR" ]]; then
    echo "（暂无：基础目录不存在）"
    return 0
  fi

  # 避免通配符无匹配时报错
  shopt -s nullglob
  local dirs=("$BASE_DIR"/*)
  shopt -u nullglob

  if [[ ${#dirs[@]} -eq 0 ]]; then
    echo "（暂无：未找到任何实例目录）"
    return 0
  fi

  for d in "${dirs[@]}"; do
    [[ -d "$d" ]] || continue
    local name
    name="$(basename "$d")"
    local svc="gost-${name}"

    local active enabled
    active="$($SUDO_CMD systemctl is-active "$svc" 2>/dev/null || echo unknown)"
    enabled="$($SUDO_CMD systemctl is-enabled "$svc" 2>/dev/null || echo unknown)"

    # 简单输出
    printf " - %-20s  service=%-22s  active=%-10s  enabled=%-10s  dir=%s\n" \
      "$name" "$svc" "$active" "$enabled" "$d"
  done
}

# =======================
# 主逻辑
# =======================
main() {
  # 如果命令行传了 i+a+s，直接安装该实例
  if [[ -n "$INSTANCE_NAME" && -n "$SERVER_ADDR" && -n "$SECRET" ]]; then
    install_gost
    delete_self
    exit 0
  fi

  while true; do
    # 每次循环清空实例名，避免上一次输入影响下一次
    INSTANCE_NAME=""
    SERVER_ADDR=""
    SECRET=""

    show_menu
    read -p "请输入选项 (1-6): " choice

    case $choice in
      1) install_gost; delete_self; exit 0 ;;
      2) update_gost; delete_self; exit 0 ;;
      3) uninstall_gost; delete_self; exit 0 ;;
      4) status_instance; delete_self; exit 0 ;;
      5) list_instances; delete_self; exit 0 ;;
      6) echo "👋 退出脚本"; delete_self; exit 0 ;;
      *) echo "❌ 无效选项，请输入 1-6"; echo "" ;;
    esac
  done
}

main
