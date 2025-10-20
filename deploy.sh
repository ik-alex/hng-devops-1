#!/usr/bin/env bash
# deploy.sh - Automated deploy & remote configuration of a Dockerized app
# Usage: ./deploy.sh     (interactive)
#        ./deploy.sh --cleanup   (runs cleanup on remote host then exits)
set -euo pipefail
IFS=$'\n\t'

########################################
# Globals & defaults
########################################
LOG_DIR="$(pwd)"
TS="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${LOG_DIR}/deploy_${TS}.log"
EXIT_CODE=0
CLEANUP_MODE=0

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Trap / logging
exec > >(tee -a "${LOG_FILE}") 2>&1

function info()  { printf "${GREEN}[INFO] %s${NC}\n" "$*"; }
function warn()  { printf "${YELLOW}[WARN] %s${NC}\n" "$*"; }
function error() { printf "${RED}[ERROR] %s${NC}\n" "$*"; }

function finish {
  rc=$?
  if [[ $rc -ne 0 ]]; then
    error "Script exited with code $rc. See log: ${LOG_FILE}"
  else
    info "Done. Log: ${LOG_FILE}"
  fi
}
trap finish EXIT

# On unexpected errors, print message and exit with non-zero
function on_err {
  local rc=$?
  error "An unexpected error occurred (exit code ${rc}). Aborting."
  EXIT_CODE=$rc
  exit "${rc}"
}
trap on_err ERR

########################################
# Helper functions
########################################
function prompt_read() {
  local varname="$1"; local prompt="$2"; local default="${3:-}"
  local silent="${4:-0}"   # 1 = silent (no echo), for PAT & keys
  local value
  if [[ "${silent}" -eq 1 ]]; then
    read -r -s -p "${prompt}" value
    echo
  else
    if [[ -n "${default}" ]]; then
      read -r -p "${prompt} [${default}]: " value
      value="${value:-${default}}"
    else
      read -r -p "${prompt}: " value
    fi
  fi
  printf -v "${varname}" '%s' "${value}"
}

function assert_command_exists() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    error "Required command '${cmd}' not found locally. Please install it and re-run."
    exit 2
  fi
}

function safe_ssh() {
  local ssh_user="$1"; local ssh_host="$2"; shift 2
  local key_opt=()
  if [[ -n "${SSH_KEY_PATH:-}" ]]; then
    key_opt=(-i "${SSH_KEY_PATH}")
  fi
  ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "${key_opt[@]}" "${ssh_user}@${ssh_host}" "$@"
}

function remote_copy() {
  local src="$1"; local dest_user="$2"; local dest_host="$3"; local dest_path="$4"
  local key_opt=()
  if [[ -n "${SSH_KEY_PATH:-}" ]]; then
    key_opt=(-e "ssh -i ${SSH_KEY_PATH} -o BatchMode=yes -o StrictHostKeyChecking=accept-new")
  fi
  rsync -az --delete ${key_opt[@]} "${src}" "${dest_user}@${dest_host}:${dest_path}"
}

function detect_pkg_manager_cmds() {
  # returns global PKG_INSTALL PKG_UPDATE PKG_CHECK PKG_SERVICE_MANAGER
  if safe_ssh "${REMOTE_USER}" "${REMOTE_HOST}" 'command -v apt-get >/dev/null 2>&1' >/dev/null 2>&1; then
    PKG_INSTALL='sudo apt-get install -y'
    PKG_UPDATE='sudo apt-get update -y'
    PKG_CHECK='dpkg -l'
    PKG_SERVICE_MANAGER='systemctl'
  elif safe_ssh "${REMOTE_USER}" "${REMOTE_HOST}" 'command -v dnf >/dev/null 2>&1' >/dev/null 2>&1; then
    PKG_INSTALL='sudo dnf install -y'
    PKG_UPDATE='sudo dnf makecache -y'
    PKG_CHECK='rpm -qa'
    PKG_SERVICE_MANAGER='systemctl'
  elif safe_ssh "${REMOTE_USER}" "${REMOTE_HOST}" 'command -v yum >/dev/null 2>&1' >/dev/null 2>&1; then
    PKG_INSTALL='sudo yum install -y'
    PKG_UPDATE='sudo yum makecache -y'
    PKG_CHECK='rpm -qa'
    PKG_SERVICE_MANAGER='systemctl'
  else
    error "Unsupported remote package manager. Please ensure apt/yum/dnf exists on remote."
    exit 3
  fi
}

########################################
# Parse args
########################################
if [[ "${1:-}" == "--cleanup" ]]; then
  CLEANUP_MODE=1
fi

########################################
# Preconditions - local
########################################
assert_command_exists ssh
assert_command_exists rsync
assert_command_exists git
assert_command_exists awk
assert_command_exists sed
assert_command_exists curl || true   # curl optional locally (used for validation)

########################################
# 1) Collect Parameters from User Input
########################################
if [[ "${CLEANUP_MODE}" -eq 1 ]]; then
  info "Running in CLEANUP mode. You will be prompted for remote details."
fi

prompt_read GIT_REPO "Git repository URL (HTTPS, e.g. https://github.com/org/repo.git)"
while [[ -z "${GIT_REPO}" ]]; do
  warn "Repository URL is required."
  prompt_read GIT_REPO "Git repository URL"
done

prompt_read PAT "Personal Access Token (PAT) - will not be echoed" "" 1
while [[ -z "${PAT}" ]]; do
  warn "PAT is required for private repo access (or leave blank if repo is public)."
  prompt_read PAT "Personal Access Token (PAT) - will not be echoed" "" 1
done

prompt_read BRANCH "Branch name (press enter for default 'main')" "main"
prompt_read REMOTE_USER "Remote server SSH username"
prompt_read REMOTE_HOST "Remote server IP or hostname"
prompt_read SSH_KEY_PATH "SSH private key path (absolute) (press enter to use default '~/.ssh/id_rsa')" "~/.ssh/id_rsa"
SSH_KEY_PATH="${SSH_KEY_PATH/#\~/$HOME}"  # expand ~
if [[ ! -f "${SSH_KEY_PATH}" ]]; then
  warn "SSH key ${SSH_KEY_PATH} not found locally. You might still succeed if agent has keys loaded."
fi

prompt_read APP_PORT "Application internal container port (e.g. 3000)"
while ! [[ "${APP_PORT}" =~ ^[0-9]+$ ]]; do
  warn "Port must be an integer."
  prompt_read APP_PORT "Application internal container port (e.g. 3000)"
done

# Optional remote deploy path and container name
prompt_read REMOTE_DEPLOY_DIR "Remote deployment directory (press enter for /opt/apps/<repo>)"
if [[ -z "${REMOTE_DEPLOY_DIR}" ]]; then
  # derive from repo URL
  REPO_NAME="$(basename -s .git "${GIT_REPO}" | sed 's/[^a-zA-Z0-9_-]/_/g')"
  REMOTE_DEPLOY_DIR="/opt/apps/${REPO_NAME}"
else
  REPO_NAME="$(basename -s .git "${GIT_REPO}" | sed 's/[^a-zA-Z0-9_-]/_/g')"
fi

CONTAINER_NAME="${REPO_NAME}_container"
NGINX_CONF_NAME="${REPO_NAME}.conf"

info "Parameters collected. Repository=${GIT_REPO}, Branch=${BRANCH}, Remote=${REMOTE_USER}@${REMOTE_HOST}, RemoteDir=${REMOTE_DEPLOY_DIR}, AppPort=${APP_PORT}"

########################################
# 2) Clone the Repository (local workspace)
########################################
WORKDIR="$(mktemp -d /tmp/deploy_${REPO_NAME}_XXXX)"
info "Using temporary working dir: ${WORKDIR}"
cd "${WORKDIR}"

# Create temporary GIT_ASKPASS that returns PAT to git without showing PAT on argv
GIT_ASKPASS_SH="$(mktemp)"
chmod 700 "${GIT_ASKPASS_SH}"
cat > "${GIT_ASKPASS_SH}" <<'EOF'
#!/usr/bin/env bash
# prints PAT supplied via env variable GIT_PAT
echo "$GIT_PAT"
EOF

export GIT_ASKPASS="${GIT_ASKPASS_SH}"
export GIT_PAT="${PAT}"
export GIT_TERMINAL_PROMPT=0

# Prepare clone URL: allow users to provide e.g. git@ or https://; if ssh-style, warn PAT won't be used
if [[ "${GIT_REPO}" =~ ^git@ ]]; then
  warn "Repository appears to be SSH-style (git@...). PAT won't be used; ensure your SSH key has access."
  git clone --branch "${BRANCH}" --single-branch "${GIT_REPO}" "${REPO_NAME}" || {
    error "git clone failed for SSH repo."
    exit 10
  }
else
  # HTTPS
  info "Cloning HTTPS repo using temporary GIT_ASKPASS helper"
  if git clone --branch "${BRANCH}" --single-branch "${GIT_REPO}" "${REPO_NAME}"; then
    info "Repository cloned successfully."
  else
    # If clone failed maybe branch doesn't exist; try clone default then checkout
    warn "Failed to clone branch '${BRANCH}' directly; attempting full clone and checkout."
    rm -rf "${REPO_NAME}"
    git clone "${GIT_REPO}" "${REPO_NAME}"
    cd "${REPO_NAME}"
    git fetch --all
    git checkout "${BRANCH}" || {
      error "Branch '${BRANCH}' not found."
      exit 11
    }
    cd ..
  fi
fi

# cleanup GIT_ASKPASS file and env var
rm -f "${GIT_ASKPASS_SH}"
unset GIT_ASKPASS GIT_PAT GIT_TERMINAL_PROMPT

cd "${REPO_NAME}"

# 3) Verify Dockerfile or docker-compose.yml exists
if [[ -f "Dockerfile" ]] || [[ -f "docker-compose.yml" ]] || [[ -f "docker-compose.yaml" ]]; then
  info "Found Dockerfile or docker-compose (good)."
else
  error "No Dockerfile or docker-compose.yml found in repository root."
  exit 12
fi

########################################
# 4) SSH connectivity checks
########################################
info "Testing SSH connectivity to ${REMOTE_USER}@${REMOTE_HOST}..."
SSH_KEY_OPT=(-i "${SSH_KEY_PATH}")
if ssh -o BatchMode=yes -o ConnectTimeout=10 -i "${SSH_KEY_PATH}" "${REMOTE_USER}@${REMOTE_HOST}" 'echo SSH_OK' >/dev/null 2>&1; then
  info "SSH successful."
else
  error "Unable to SSH to ${REMOTE_USER}@${REMOTE_HOST} using key ${SSH_KEY_PATH}. Check connectivity and keys."
  exit 13
fi

# 4b) detect remote package manager
detect_pkg_manager_cmds
info "Remote package manager detected. Will use pkg commands."

########################################
# If cleanup mode: perform remote cleanup and exit
########################################
if [[ "${CLEANUP_MODE}" -eq 1 ]]; then
  info "Performing cleanup on remote host ${REMOTE_USER}@${REMOTE_HOST} ..."
  safe_ssh "${REMOTE_USER}" "${REMOTE_HOST}" bash -s <<EOF
set -euo pipefail
sudo ${PKG_SERVICE_MANAGER} stop nginx || true
sudo docker rm -f "${CONTAINER_NAME}" || true
sudo docker rmi "${REPO_NAME}:latest" || true
sudo rm -rf "${REMOTE_DEPLOY_DIR}"
sudo rm -f /etc/nginx/sites-enabled/${NGINX_CONF_NAME} /etc/nginx/sites-available/${NGINX_CONF_NAME} || true
sudo ${PKG_SERVICE_MANAGER} restart nginx || true
EOF
  info "Remote cleanup completed."
  exit 0
fi

########################################
# 5) Prepare the Remote Environment (install Docker, Compose, Nginx)
########################################
info "Preparing remote environment: updating packages and installing Docker, Docker Compose, Nginx (if missing)."

safe_ssh "${REMOTE_USER}" "${REMOTE_HOST}" bash -s <<'REMOTE_SETUP'
set -euo pipefail
# Detect package manager locally on remote
if command -v apt-get >/dev/null 2>&1; then
  PM=apt
elif command -v dnf >/dev/null 2>&1; then
  PM=dnf
elif command -v yum >/dev/null 2>&1; then
  PM=yum
else
  echo "UNSUPPORTED_PM"
  exit 2
fi
echo "PM=${PM}"

if [[ "${PM}" = "apt" ]]; then
  sudo apt-get update -y
  sudo apt-get install -y ca-certificates curl gnupg lsb-release apt-transport-https software-properties-common
  # Docker official repo
  if ! command -v docker >/dev/null 2>&1; then
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
      $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt-get update -y
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
  fi
  # nginx
  if ! command -v nginx >/dev/null 2>&1; then
    sudo apt-get install -y nginx
  fi
elif [[ "${PM}" = "dnf" || "${PM}" = "yum" ]]; then
  if [[ "${PM}" = "dnf" ]]; then
    sudo dnf makecache -y
  else
    sudo yum makecache -y
  fi
  if ! command -v docker >/dev/null 2>&1; then
    # Use distro's package or get docker repo (simple approach)
    sudo ${PM} install -y yum-utils
    sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo || true
    sudo ${PM} install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    sudo systemctl enable --now docker
  fi
  if ! command -v nginx >/dev/null 2>&1; then
    sudo ${PM} install -y nginx
  fi
fi

# Add user to docker group if docker exists
if command -v docker >/dev/null 2>&1; then
  sudo usermod -aG docker "${USER}" || true
  sudo systemctl enable --now docker || true
fi

# Ensure nginx is enabled
if command -v nginx >/dev/null 2>&1; then
  sudo systemctl enable --now nginx || true
fi

# Print versions
echo "DOCKER_VERSION: $(docker --version 2>/dev/null || echo 'not_installed')"
echo "NGINX_VERSION: $(nginx -v 2>&1 || echo 'not_installed')"
REMOTE_SETUP
info "Remote environment preparation completed."

########################################
# 6) Deploy the Dockerized Application
########################################
info "Transferring project files to remote ${REMOTE_DEPLOY_DIR} (rsync)."
# Create remote dir (owner will be remote user)
safe_ssh "${REMOTE_USER}" "${REMOTE_HOST}" "sudo mkdir -p '${REMOTE_DEPLOY_DIR}' && sudo chown -R ${REMOTE_USER}:${REMOTE_USER} '${REMOTE_DEPLOY_DIR}'"

# Copy
remote_copy "./" "${REMOTE_USER}" "${REMOTE_HOST}" "${REMOTE_DEPLOY_DIR}/"
info "Files transferred."

# Remote build & run
info "Building and launching containers on remote host."

# Create remote deploy script to execute the build/run safely (idempotent)
safe_ssh "${REMOTE_USER}" "${REMOTE_HOST}" bash -s <<EOF
set -euo pipefail
cd "${REMOTE_DEPLOY_DIR}"

# Stop and remove any existing container with same name
if sudo docker ps -a --format '{{.Names}}' | grep -x "${CONTAINER_NAME}" >/dev/null 2>&1; then
  echo "Stopping existing container ${CONTAINER_NAME}..."
  sudo docker rm -f "${CONTAINER_NAME}" || true
fi

# If docker-compose exists in repo, use it
if [[ -f "docker-compose.yml" ]] || [[ -f "docker-compose.yaml" ]]; then
  # ensure no duplicate networks: docker-compose down first
  echo "Using docker-compose to build and start..."
  sudo docker compose down || true
  sudo docker compose pull || true
  sudo docker compose up -d --build
else
  # Build image from Dockerfile
  echo "Building Docker image ${REPO_NAME}:latest"
  sudo docker build -t "${REPO_NAME}:latest" .
  # Run container (map a random host port OR fixed port - we'll expose internal port to host)
  # Stop any container with same name handled above. Remove old image if needed.
  sudo docker run -d --name "${CONTAINER_NAME}" -p ${APP_PORT}:${APP_PORT} --restart unless-stopped "${REPO_NAME}:latest"
fi

# Wait and check container status
sleep 3
if sudo docker ps --format '{{.Names}}' | grep -x "${CONTAINER_NAME}" >/dev/null 2>&1; then
  echo "Container ${CONTAINER_NAME} is running."
else
  echo "ERROR: Container ${CONTAINER_NAME} failed to start."
  sudo docker logs "${CONTAINER_NAME}" || true
  exit 20
fi
EOF

info "Remote container build/run completed."

########################################
# 7) Configure Nginx as Reverse Proxy
########################################
info "Configuring Nginx reverse proxy on remote host to forward :80 -> :${APP_PORT} (container)."

# Create nginx config locally (then rsync or cat via ssh)
NGINX_CONF_CONTENT="
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    access_log /var/log/nginx/${REPO_NAME}_access.log;
    error_log /var/log/nginx/${REPO_NAME}_error.log;
}
"

# Push Nginx config
TMP_NGINX_CONF="$(mktemp)"
echo "${NGINX_CONF_CONTENT}" > "${TMP_NGINX_CONF}"

safe_ssh "${REMOTE_USER}" "${REMOTE_HOST}" "sudo mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled || true"
remote_copy "${TMP_NGINX_CONF}" "${REMOTE_USER}" "${REMOTE_HOST}" "/tmp/${NGINX_CONF_NAME}"
safe_ssh "${REMOTE_USER}" "${REMOTE_HOST}" bash -s <<EOF
set -euo pipefail
sudo mv /tmp/${NGINX_CONF_NAME} /etc/nginx/sites-available/${NGINX_CONF_NAME}
sudo ln -sf /etc/nginx/sites-available/${NGINX_CONF_NAME} /etc/nginx/sites-enabled/${NGINX_CONF_NAME}
# Remove default if it conflicts
sudo rm -f /etc/nginx/sites-enabled/default || true
# Test and reload nginx
sudo nginx -t
sudo systemctl reload nginx
EOF
rm -f "${TMP_NGINX_CONF}"

info "Nginx configured and reloaded."

########################################
# 8) Validate Deployment
########################################
info "Validating deployment..."

# 8a) Check Docker running and container health
safe_ssh "${REMOTE_USER}" "${REMOTE_HOST}" bash -s <<EOF
set -euo pipefail
echo "=== docker version ==="
docker --version || true
echo "--- docker ps ---"
docker ps --filter "name=${CONTAINER_NAME}" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
# If container has HEALTHCHECK, inspect
if docker inspect --format='{{json .State.Health }}' ${CONTAINER_NAME} >/dev/null 2>&1; then
  docker inspect --format='{{json .State.Health }}' ${CONTAINER_NAME} || true
fi
EOF

# 8b) Test endpoint locally on remote (curl)
info "Testing HTTP endpoint from remote host (curl http://127.0.0.1:${APP_PORT})..."
safe_ssh "${REMOTE_USER}" "${REMOTE_HOST}" "curl -sS -o /dev/null -w '%{http_code}\\n' http://127.0.0.1:${APP_PORT} || true"

# 8c) Test remotely from local machine (curl to remote IP)
if command -v curl >/dev/null 2>&1; then
  info "Testing HTTP endpoint from local machine (curl http://${REMOTE_HOST})"
  HTTP_CODE="$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 10 "http://${REMOTE_HOST}")" || HTTP_CODE="000"
  info "HTTP status code from remote host public IP: ${HTTP_CODE}"
else
  warn "curl not installed locally; skipping local check to remote."
fi

########################################
# 9) Logging and Exit
########################################
info "Deployment finished. Review logs at ${LOG_FILE} for details."

exit 0
