#!/usr/bin/env sh
# synctool-relay — 256MB/512MB 低配小鸡免 Docker 单静态二进制 systemd 一键安装脚本
# 省去 dockerd/containerd 80~120MB 常驻内存，空闲 RSS < 15 MiB。
#
# 用法示例：
#   sudo SYNCTOOL_PUBLIC_HOST=1.2.3.4 sh install-systemd.sh
#   sudo SYNCTOOL_PUBLIC_HOST=1.2.3.4 SYNCTOOL_SPOOL=off sh install-systemd.sh   # 手动彻底关闭离线暂存

set -eu

REPO="${SYNCTOOL_REPO:-yellowdking/synctool}"
VERSION="${SYNCTOOL_VERSION:-latest}"
BIN_PATH="/usr/local/bin/synctool-relay"
STATE_DIR="/var/lib/synctool-relay"
ENV_FILE="/etc/synctool-relay.env"
SERVICE_FILE="/etc/systemd/system/synctool-relay.service"

if [ "$(id -u)" -ne 0 ]; then
  echo "请使用 root / sudo 运行此脚本" >&2
  exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) GOARCH="amd64" ;;
  aarch64|arm64) GOARCH="arm64" ;;
  *) echo "暂不支持的架构: $ARCH" >&2; exit 1 ;;
esac

if [ "$VERSION" = "latest" ]; then
  DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/synctool-relay_linux_${GOARCH}"
else
  DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/synctool-relay_linux_${GOARCH}"
fi

echo "==> 下载 synctool-relay (linux/${GOARCH})..."
TMP_BIN="$(mktemp)"
curl -fsSL "$DOWNLOAD_URL" -o "$TMP_BIN"
install -m 0755 "$TMP_BIN" "$BIN_PATH"
rm -f "$TMP_BIN"

mkdir -p "$STATE_DIR"
chmod 0700 "$STATE_DIR"

# 创建专用非特权系统用户，避免服务以 root 身份运行
if ! id -u synctool >/dev/null 2>&1; then
  if command -v useradd >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin synctool
  else
    adduser -S -H -s /sbin/nologin synctool
  fi
fi

if [ ! -f "$ENV_FILE" ]; then
  cat > "$ENV_FILE" <<EOF
SYNCTOOL_LISTEN=${SYNCTOOL_LISTEN:-:54843}
SYNCTOOL_PUBLIC_HOST=${SYNCTOOL_PUBLIC_HOST:-}
# auto 自动识别小鸡内存档位（<768MB 自动走 nano）；可改为 nano / standard / media
SYNCTOOL_PROFILE=${SYNCTOOL_PROFILE:-auto}
# auto 跟随档位；设为 off 可手动彻底关闭离线暂存（仅保留 Mode A 实时零落盘管道）
SYNCTOOL_SPOOL=${SYNCTOOL_SPOOL:-auto}
SYNCTOOL_TLS=${SYNCTOOL_TLS:-selfsigned}
SYNCTOOL_DATA_DIR=${STATE_DIR}
SYNCTOOL_MAX_BANDWIDTH_MBPS=${SYNCTOOL_MAX_BANDWIDTH_MBPS:-0}
EOF
  chown root:synctool "$ENV_FILE"
  chmod 0640 "$ENV_FILE"
fi

echo "==> 初始化私有 AccessKey 与 730 天自签证书..."
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a
"$BIN_PATH" init --data-dir "$STATE_DIR" --public-host "${SYNCTOOL_PUBLIC_HOST:-}" --listen "${SYNCTOOL_LISTEN:-:54843}" --tls "${SYNCTOOL_TLS:-selfsigned}"
chown -R synctool:synctool "$STATE_DIR"
chmod 0700 "$STATE_DIR"

# 按宿主机物理内存自适应默认 systemd MemoryMax（与 auto 档位对齐，防 standard/media 误触发 OOM）
MEM_KB="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 524288)"
DEFAULT_MEM_MAX="64M"
if [ "${MEM_KB:-0}" -ge 2097152 ]; then
  DEFAULT_MEM_MAX="512M"
elif [ "${MEM_KB:-0}" -ge 786432 ]; then
  DEFAULT_MEM_MAX="224M"
fi
SYSTEMD_MEM_MAX="${SYNCTOOL_MEMORY_MAX:-$DEFAULT_MEM_MAX}"

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=synctool zero-trust on-demand encrypted sync relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=synctool
Group=synctool
EnvironmentFile=${ENV_FILE}
ExecStart=${BIN_PATH} serve
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=3s

# 自适应内存上限（256MB/512MB 小鸡默认 64M）与最小权限隔离
MemoryMax=${SYSTEMD_MEM_MAX}
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${STATE_DIR}
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictRealtime=yes
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now synctool-relay.service
echo ""
echo "==> synctool-relay 已启动！查看状态：systemctl status synctool-relay"
echo "==> 如需手动关闭离线暂存：在 ${ENV_FILE} 中设置 SYNCTOOL_SPOOL=off 后执行 systemctl restart synctool-relay"
