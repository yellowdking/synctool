#!/usr/bin/env sh
# synctool-relay — 256MB/512MB 低配小鸡免 Docker 单静态二进制 systemd 一键安装脚本
# 省去 dockerd/containerd 80~120MB 常驻内存，空闲 RSS < 15 MiB。
#
# 用法示例（同时支持 CLI 参数与环境变量）：
#   sudo sh deploy/install-systemd.sh --public-host 1.2.3.4 --profile auto
#   sudo sh deploy/install-systemd.sh --public-host 1.2.3.4 --profile nano --spool off
#   sudo SYNCTOOL_PUBLIC_HOST=1.2.3.4 SYNCTOOL_SPOOL=off sh deploy/install-systemd.sh

set -eu

usage() {
  cat >&2 <<'EOF'
Usage: sudo sh install-systemd.sh [options]

Options:
  --public-host <ip-or-domain>   Public IP or domain for TLS SAN & onboarding URI (env SYNCTOOL_PUBLIC_HOST)
  --profile <auto|nano|standard|media>  VPS preset (default: auto, env SYNCTOOL_PROFILE)
  --spool <auto|off|memory|disk> Offline spool mode (default: auto, env SYNCTOOL_SPOOL)
  --listen <addr>                Listen address (default: :54843, env SYNCTOOL_LISTEN)
  --tls <selfsigned|cert|off>    TLS mode (default: selfsigned, env SYNCTOOL_TLS)
  --tls-cert <path>              Certificate PEM path when --tls=cert (env SYNCTOOL_TLS_CERT)
  --tls-key <path>               Private key PEM path when --tls=cert (env SYNCTOOL_TLS_KEY)
  --cors-origins <origins>       Comma-separated allowed CORS origins or * (env SYNCTOOL_CORS_ORIGINS)
  --max-bandwidth-mbps <mbps>    Optional global bandwidth cap in Mbps (env SYNCTOOL_MAX_BANDWIDTH_MBPS)
  --version <tag|latest>         Release version tag to download (default: latest, env SYNCTOOL_VERSION)
  -h, --help                     Show this help message
EOF
}

CLI_PUBLIC_HOST=""
CLI_PROFILE=""
CLI_SPOOL=""
CLI_LISTEN=""
CLI_TLS=""
CLI_TLS_CERT=""
CLI_TLS_KEY=""
CLI_CORS_ORIGINS=""
CLI_MAX_BW=""
CLI_VERSION=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --public-host)
      [ "$#" -ge 2 ] || { echo "missing value for --public-host" >&2; exit 2; }
      CLI_PUBLIC_HOST="$2"; shift 2 ;;
    --public-host=*)
      CLI_PUBLIC_HOST="${1#*=}"; shift ;;
    --profile)
      [ "$#" -ge 2 ] || { echo "missing value for --profile" >&2; exit 2; }
      CLI_PROFILE="$2"; shift 2 ;;
    --profile=*)
      CLI_PROFILE="${1#*=}"; shift ;;
    --spool)
      [ "$#" -ge 2 ] || { echo "missing value for --spool" >&2; exit 2; }
      CLI_SPOOL="$2"; shift 2 ;;
    --spool=*)
      CLI_SPOOL="${1#*=}"; shift ;;
    --listen)
      [ "$#" -ge 2 ] || { echo "missing value for --listen" >&2; exit 2; }
      CLI_LISTEN="$2"; shift 2 ;;
    --listen=*)
      CLI_LISTEN="${1#*=}"; shift ;;
    --tls)
      [ "$#" -ge 2 ] || { echo "missing value for --tls" >&2; exit 2; }
      CLI_TLS="$2"; shift 2 ;;
    --tls=*)
      CLI_TLS="${1#*=}"; shift ;;
    --tls-cert)
      [ "$#" -ge 2 ] || { echo "missing value for --tls-cert" >&2; exit 2; }
      CLI_TLS_CERT="$2"; shift 2 ;;
    --tls-cert=*)
      CLI_TLS_CERT="${1#*=}"; shift ;;
    --tls-key)
      [ "$#" -ge 2 ] || { echo "missing value for --tls-key" >&2; exit 2; }
      CLI_TLS_KEY="$2"; shift 2 ;;
    --tls-key=*)
      CLI_TLS_KEY="${1#*=}"; shift ;;
    --cors-origins)
      [ "$#" -ge 2 ] || { echo "missing value for --cors-origins" >&2; exit 2; }
      CLI_CORS_ORIGINS="$2"; shift 2 ;;
    --cors-origins=*)
      CLI_CORS_ORIGINS="${1#*=}"; shift ;;
    --max-bandwidth-mbps)
      [ "$#" -ge 2 ] || { echo "missing value for --max-bandwidth-mbps" >&2; exit 2; }
      CLI_MAX_BW="$2"; shift 2 ;;
    --max-bandwidth-mbps=*)
      CLI_MAX_BW="${1#*=}"; shift ;;
    --version)
      [ "$#" -ge 2 ] || { echo "missing value for --version" >&2; exit 2; }
      CLI_VERSION="$2"; shift 2 ;;
    --version=*)
      CLI_VERSION="${1#*=}"; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "未知参数: $1" >&2
      usage
      exit 2 ;;
  esac
done

[ -n "$CLI_PUBLIC_HOST" ] && SYNCTOOL_PUBLIC_HOST="$CLI_PUBLIC_HOST"
[ -n "$CLI_PROFILE" ] && SYNCTOOL_PROFILE="$CLI_PROFILE"
[ -n "$CLI_SPOOL" ] && SYNCTOOL_SPOOL="$CLI_SPOOL"
[ -n "$CLI_LISTEN" ] && SYNCTOOL_LISTEN="$CLI_LISTEN"
[ -n "$CLI_TLS" ] && SYNCTOOL_TLS="$CLI_TLS"
[ -n "$CLI_TLS_CERT" ] && SYNCTOOL_TLS_CERT="$CLI_TLS_CERT"
[ -n "$CLI_TLS_KEY" ] && SYNCTOOL_TLS_KEY="$CLI_TLS_KEY"
[ -n "$CLI_CORS_ORIGINS" ] && SYNCTOOL_CORS_ORIGINS="$CLI_CORS_ORIGINS"
[ -n "$CLI_MAX_BW" ] && SYNCTOOL_MAX_BANDWIDTH_MBPS="$CLI_MAX_BW"
[ -n "$CLI_VERSION" ] && SYNCTOOL_VERSION="$CLI_VERSION"

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

ASSET_NAME="synctool-relay_linux_${GOARCH}"
if [ "$VERSION" = "latest" ]; then
  BASE_URL="https://github.com/${REPO}/releases/latest/download"
else
  BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
fi

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

echo "==> 下载 ${ASSET_NAME} 与 SHA256SUMS.txt..."
curl -fsSL "${BASE_URL}/${ASSET_NAME}" -o "${TMP_DIR}/${ASSET_NAME}"
curl -fsSL "${BASE_URL}/SHA256SUMS.txt" -o "${TMP_DIR}/SHA256SUMS.txt"

echo "==> 校验 SHA-256 签名摘要..."
if ! grep -Eq "[[:space:]]\*?${ASSET_NAME}\$" "${TMP_DIR}/SHA256SUMS.txt"; then
  echo "错误：SHA256SUMS.txt 中未找到 ${ASSET_NAME} 条目，拒绝安装！" >&2
  exit 1
fi
(cd "$TMP_DIR" && sha256sum -c --ignore-missing SHA256SUMS.txt)

install -m 0755 "${TMP_DIR}/${ASSET_NAME}" "$BIN_PATH"

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

# 若已存在历史配置，先加载旧值再用本次显式传入的 CLI/环境变量覆盖
if [ -f "$ENV_FILE" ]; then
  SAVED_PUBLIC_HOST="${SYNCTOOL_PUBLIC_HOST-__UNSET__}"
  SAVED_PROFILE="${SYNCTOOL_PROFILE-__UNSET__}"
  SAVED_SPOOL="${SYNCTOOL_SPOOL-__UNSET__}"
  SAVED_LISTEN="${SYNCTOOL_LISTEN-__UNSET__}"
  SAVED_TLS="${SYNCTOOL_TLS-__UNSET__}"
  SAVED_TLS_CERT="${SYNCTOOL_TLS_CERT-__UNSET__}"
  SAVED_TLS_KEY="${SYNCTOOL_TLS_KEY-__UNSET__}"
  SAVED_CORS="${SYNCTOOL_CORS_ORIGINS-__UNSET__}"
  SAVED_BW="${SYNCTOOL_MAX_BANDWIDTH_MBPS-__UNSET__}"
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
  [ "$SAVED_PUBLIC_HOST" != "__UNSET__" ] && SYNCTOOL_PUBLIC_HOST="$SAVED_PUBLIC_HOST"
  [ "$SAVED_PROFILE" != "__UNSET__" ] && SYNCTOOL_PROFILE="$SAVED_PROFILE"
  [ "$SAVED_SPOOL" != "__UNSET__" ] && SYNCTOOL_SPOOL="$SAVED_SPOOL"
  [ "$SAVED_LISTEN" != "__UNSET__" ] && SYNCTOOL_LISTEN="$SAVED_LISTEN"
  [ "$SAVED_TLS" != "__UNSET__" ] && SYNCTOOL_TLS="$SAVED_TLS"
  [ "$SAVED_TLS_CERT" != "__UNSET__" ] && SYNCTOOL_TLS_CERT="$SAVED_TLS_CERT"
  [ "$SAVED_TLS_KEY" != "__UNSET__" ] && SYNCTOOL_TLS_KEY="$SAVED_TLS_KEY"
  [ "$SAVED_CORS" != "__UNSET__" ] && SYNCTOOL_CORS_ORIGINS="$SAVED_CORS"
  [ "$SAVED_BW" != "__UNSET__" ] && SYNCTOOL_MAX_BANDWIDTH_MBPS="$SAVED_BW"
fi

cat > "$ENV_FILE" <<EOF
SYNCTOOL_LISTEN=${SYNCTOOL_LISTEN:-:54843}
SYNCTOOL_PUBLIC_HOST=${SYNCTOOL_PUBLIC_HOST:-}
# 预设档位：auto | nano | standard | media
SYNCTOOL_PROFILE=${SYNCTOOL_PROFILE:-auto}
# auto 跟随档位；设为 off 可手动彻底关闭离线暂存（仅保留 Mode A 实时零落盘管道）
SYNCTOOL_SPOOL=${SYNCTOOL_SPOOL:-auto}
SYNCTOOL_TLS=${SYNCTOOL_TLS:-selfsigned}
SYNCTOOL_TLS_CERT=${SYNCTOOL_TLS_CERT:-}
SYNCTOOL_TLS_KEY=${SYNCTOOL_TLS_KEY:-}
SYNCTOOL_CORS_ORIGINS=${SYNCTOOL_CORS_ORIGINS:-}
SYNCTOOL_DATA_DIR=${STATE_DIR}
SYNCTOOL_MAX_BANDWIDTH_MBPS=${SYNCTOOL_MAX_BANDWIDTH_MBPS:-0}
EOF
chown root:synctool "$ENV_FILE"
chmod 0640 "$ENV_FILE"

echo "==> 初始化私有 AccessKey 与 730 天自签证书..."
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

INIT_ARGS="--data-dir $STATE_DIR --public-host ${SYNCTOOL_PUBLIC_HOST:-} --listen ${SYNCTOOL_LISTEN:-:54843} --profile ${SYNCTOOL_PROFILE:-auto} --spool ${SYNCTOOL_SPOOL:-auto} --tls ${SYNCTOOL_TLS:-selfsigned}"
if [ -n "${SYNCTOOL_TLS_CERT:-}" ]; then
  INIT_ARGS="$INIT_ARGS --tls-cert ${SYNCTOOL_TLS_CERT}"
fi
if [ -n "${SYNCTOOL_TLS_KEY:-}" ]; then
  INIT_ARGS="$INIT_ARGS --tls-key ${SYNCTOOL_TLS_KEY}"
fi
# shellcheck disable=SC2086
"$BIN_PATH" init $INIT_ARGS
chown -R synctool:synctool "$STATE_DIR"
chmod 0700 "$STATE_DIR"

# 按所选档位与宿主机物理内存对齐 systemd MemoryMax（nano=256M, standard=384M, media=1024M）
MEM_KB="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 1048576)"
EFFECTIVE_PROFILE="${SYNCTOOL_PROFILE:-auto}"
case "$EFFECTIVE_PROFILE" in
  nano)
    DEFAULT_MEM_MAX="256M" ;;
  standard)
    DEFAULT_MEM_MAX="384M" ;;
  media)
    DEFAULT_MEM_MAX="1024M" ;;
  *)
    if [ "${MEM_KB:-0}" -ge 1572864 ]; then
      DEFAULT_MEM_MAX="1024M"
    elif [ "${MEM_KB:-0}" -ge 786432 ]; then
      DEFAULT_MEM_MAX="384M"
    else
      DEFAULT_MEM_MAX="256M"
      # <768MB 小内存宿主机在 auto 模式下显式落定 nano，避免 256M MemoryMax 被识别为 standard
      sed -i 's/^SYNCTOOL_PROFILE=auto$/SYNCTOOL_PROFILE=nano/' "$ENV_FILE" 2>/dev/null || true
    fi
    ;;
esac
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

# 档位对齐内存上限（nano=256M / standard=384M / media=1024M）与最小权限隔离
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
systemctl enable synctool-relay.service
systemctl restart synctool-relay.service
echo ""
echo "==> synctool-relay 已启动！查看状态：systemctl status synctool-relay"
echo "==> 如需手动关闭离线暂存：在 ${ENV_FILE} 中设置 SYNCTOOL_SPOOL=off 后执行 systemctl restart synctool-relay"
