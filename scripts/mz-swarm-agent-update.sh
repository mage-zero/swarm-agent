#!/usr/bin/env bash
set -euo pipefail

# MageZero Swarm Agent Updater
#
# This script is the ONLY thing that swaps the agent binary and restarts the service.
# The agent never modifies its own binary — this keeps the upgrade path stable.
#
# On every tick (15-minute systemd timer):
# 1. Fetch GitHub releases list (all releases, not just latest)
# 2. Identify all releases newer than current version
# 3. Download each missing release into /opt/mage-zero/agent/releases/{version}/
# 4. Compute total downtime from changelogs
# 5. Zero-downtime path: swap binary + restart immediately
# 6. Downtime path: write upgrade-available.json, wait for agent approval
# 7. Cleanup old release directories

AGENT_DIR="${MZ_AGENT_DIR:-/opt/mage-zero/agent}"
RELEASES_DIR="${AGENT_DIR}/releases"
TARGET="${AGENT_DIR}/swarm-agent.cjs"
CHANGELOG_FILE="${AGENT_DIR}/changelog.json"
VERSION_FILE="${AGENT_DIR}/version"
UPGRADE_AVAILABLE="${AGENT_DIR}/upgrade-available.json"
UPGRADE_APPROVED="${AGENT_DIR}/upgrade-approved.json"
PROCESSING_DIR="${MZ_DEPLOY_PROCESSING_DIR:-/opt/mage-zero/deployments/processing}"
UPDATE_GRACE_MIN="${MZ_SWARM_AGENT_UPDATE_GRACE_MIN:-45}"
GITHUB_REPO="${MZ_GITHUB_REPO:-mage-zero/swarm-agent}"
CLOUD_SWARM_DIR="${MZ_CLOUD_SWARM_DIR:-/opt/mage-zero/cloud-swarm}"
CLOUD_SWARM_REPO="${MZ_CLOUD_SWARM_REPO:-git@github.com:mage-zero/cloud-swarm.git}"
CLOUD_SWARM_KEY_PATH="${MZ_CLOUD_SWARM_KEY_PATH:-/opt/mage-zero/keys/cloud-swarm-deploy}"
CLOUD_SWARM_REFRESH_ENABLED="${MZ_CLOUD_SWARM_REFRESH_ENABLED:-1}"

if ! [[ "${UPDATE_GRACE_MIN}" =~ ^[0-9]+$ ]]; then
  UPDATE_GRACE_MIN=45
fi

# --- Helper functions ---

log() {
  echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $*"
}

is_swarm_manager() {
  if ! command -v docker >/dev/null 2>&1; then
    return 1
  fi
  local control
  control="$(docker info --format '{{.Swarm.ControlAvailable}}' 2>/dev/null || echo false)"
  [[ "${control}" == "true" ]]
}

parse_version() {
  echo "${1#v}"
}

# Compare semver: returns 0 if a==b, 1 if a>b, 2 if a<b
compare_semver() {
  local a="$1" b="$2"
  if [ "$a" = "$b" ]; then return 0; fi

  local IFS='.'
  read -ra va <<< "$a"
  read -ra vb <<< "$b"

  for i in 0 1 2; do
    local na="${va[$i]:-0}" nb="${vb[$i]:-0}"
    [[ "${na}" =~ ^[0-9]+$ ]] || na=0
    [[ "${nb}" =~ ^[0-9]+$ ]] || nb=0
    if (( na > nb )); then return 1; fi
    if (( na < nb )); then return 2; fi
  done
  return 0
}

version_gt() {
  compare_semver "$1" "$2" && return 1  # equal = not greater
  local rc=$?
  [[ $rc -eq 1 ]] && return 0
  return 1
}

swap_and_restart() {
  local version="$1"
  local release_dir="${RELEASES_DIR}/${version}"

  if [[ ! -f "${release_dir}/swarm-agent.cjs" ]]; then
    log "release directory missing for ${version}; cannot swap"
    return 1
  fi

  cp "${release_dir}/swarm-agent.cjs" "${TARGET}"
  cp "${release_dir}/changelog.json" "${CHANGELOG_FILE}" 2>/dev/null || true
  echo "${version}" > "${VERSION_FILE}"

  rm -f "${UPGRADE_AVAILABLE}" "${UPGRADE_APPROVED}"

  systemctl restart mz-swarm-agent
  log "swapped to ${version} and restarted agent"

  cleanup_old_releases
}

cleanup_old_releases() {
  if [[ ! -d "${RELEASES_DIR}" ]]; then return; fi

  local running_version
  running_version="$(tr -d '[:space:]' < "${VERSION_FILE}" 2>/dev/null || echo "")"
  running_version="$(parse_version "${running_version}")"

  if [[ -z "${running_version}" ]]; then return; fi

  for dir in "${RELEASES_DIR}"/*/; do
    [[ -d "${dir}" ]] || continue
    local dir_version
    dir_version="$(basename "${dir}")"

    if compare_semver "${dir_version}" "${running_version}"; then
      continue  # equal, keep
    fi
    if version_gt "${dir_version}" "${running_version}"; then
      continue  # newer, keep
    fi
    log "cleaning up old release: ${dir_version}"
    rm -rf "${dir}"
  done
}

refresh_cloud_swarm_repo() {
  if [[ "${CLOUD_SWARM_REFRESH_ENABLED}" == "0" ]]; then
    return 0
  fi

  if ! is_swarm_manager; then
    return 0
  fi

  if ! command -v git >/dev/null 2>&1; then
    log "cloud-swarm refresh skipped: git not available"
    return 0
  fi

  if [[ ! -f "${CLOUD_SWARM_KEY_PATH}" ]]; then
    log "cloud-swarm refresh skipped: deploy key missing at ${CLOUD_SWARM_KEY_PATH}"
    return 0
  fi

  mkdir -p "$(dirname "${CLOUD_SWARM_DIR}")"
  local git_ssh_cmd="ssh -i ${CLOUD_SWARM_KEY_PATH} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"
  local checkout_failed=0

  if [[ ! -d "${CLOUD_SWARM_DIR}/.git" ]]; then
    if ! GIT_SSH_COMMAND="${git_ssh_cmd}" git clone "${CLOUD_SWARM_REPO}" "${CLOUD_SWARM_DIR}" >/dev/null 2>&1; then
      log "cloud-swarm refresh failed: clone ${CLOUD_SWARM_REPO}"
      return 0
    fi
    log "cloud-swarm refresh: cloned repository"
    return 0
  fi

  if ! GIT_SSH_COMMAND="${git_ssh_cmd}" git -C "${CLOUD_SWARM_DIR}" fetch --prune "${CLOUD_SWARM_REPO}" "+refs/heads/main:refs/remotes/origin/main" >/dev/null 2>&1; then
    log "cloud-swarm refresh failed: fetch"
    return 0
  fi

  if ! GIT_SSH_COMMAND="${git_ssh_cmd}" git -C "${CLOUD_SWARM_DIR}" checkout -B main origin/main --force >/dev/null 2>&1; then
    checkout_failed=1
  fi

  if (( checkout_failed == 1 )); then
    log "cloud-swarm refresh failed: checkout origin/main"
    return 0
  fi

  log "cloud-swarm refresh: synced to origin/main"
  return 0
}

# --- Deploy-active guard ---

MAX_AGE_SEC=$((UPDATE_GRACE_MIN * 60))
if [[ -d "${PROCESSING_DIR}" ]]; then
  newest=0
  while IFS= read -r -d '' file; do
    mtime=$(stat -c %Y "${file}" 2>/dev/null || echo 0)
    if (( mtime > newest )); then
      newest=$mtime
    fi
  done < <(find "${PROCESSING_DIR}" -maxdepth 1 -type f -name '*.json' -print0)
  if (( newest > 0 )); then
    now=$(date +%s)
    age=$(( now - newest ))
    if (( age < MAX_AGE_SEC )); then
      log "deploy active (${age}s < ${MAX_AGE_SEC}s); skipping update"
      exit 0
    fi
  fi
fi

# Best-effort cloud-swarm refresh outside active deploy windows.
# Deploy path still force-refreshes before builds as a backstop.
refresh_cloud_swarm_repo

# --- Read current version ---

CURRENT_VERSION="unknown"
if [[ -f "${VERSION_FILE}" ]]; then
  CURRENT_VERSION="$(tr -d '[:space:]' < "${VERSION_FILE}")"
fi
CURRENT_VERSION="$(parse_version "${CURRENT_VERSION}")"

if [[ ! "${CURRENT_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  log "current version '${CURRENT_VERSION}' is not stable semver; using 0.0.0 baseline"
  CURRENT_VERSION="0.0.0"
fi

log "current version: ${CURRENT_VERSION}"

# --- Fetch all GitHub releases ---

RELEASES_JSON=$(curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/releases?per_page=50" 2>/dev/null || echo "[]")

if [[ "${RELEASES_JSON}" == "[]" ]]; then
  log "no releases found or API error; skipping"
  exit 0
fi

# Parse releases into version list (sorted ascending)
VERSIONS=()
while IFS= read -r tag; do
  [[ -z "${tag}" ]] && continue
  version="$(parse_version "${tag}")"
  if [[ ! "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    continue
  fi
  if version_gt "${version}" "${CURRENT_VERSION}"; then
    VERSIONS+=("${version}")
  fi
done < <(echo "${RELEASES_JSON}" | python3 -c "
import json, re, sys
releases = json.load(sys.stdin)
stable = re.compile(r'^v?(\\d+)\\.(\\d+)\\.(\\d+)$')
tags = []
for r in releases:
    if r.get('draft') or r.get('prerelease'):
        continue
    tag = r.get('tag_name', '')
    m = stable.match(tag)
    if not m:
        continue
    tags.append((tuple(int(x) for x in m.groups()), tag))
tags.sort(key=lambda item: item[0])
for _, t in tags:
    print(t)
" 2>/dev/null)

if [[ ${#VERSIONS[@]} -eq 0 ]]; then
  log "no newer versions found"
  cleanup_old_releases
  exit 0
fi

log "found ${#VERSIONS[@]} newer version(s): ${VERSIONS[*]}"

# --- Download missing releases ---

mkdir -p "${RELEASES_DIR}"

for version in "${VERSIONS[@]}"; do
  release_dir="${RELEASES_DIR}/${version}"

  if [[ -f "${release_dir}/swarm-agent.cjs" && -f "${release_dir}/changelog.json" ]]; then
    continue
  fi

  log "downloading release ${version}..."
  mkdir -p "${release_dir}"

  tag="v${version}"
  base_url="https://github.com/${GITHUB_REPO}/releases/download/${tag}"

  if ! curl -fsSL "${base_url}/swarm-agent.cjs" -o "${release_dir}/swarm-agent.cjs.tmp"; then
    log "failed to download swarm-agent.cjs for ${version}"
    rm -rf "${release_dir}"
    continue
  fi

  if ! curl -fsSL "${base_url}/swarm-agent.cjs.sha256" -o "${release_dir}/swarm-agent.cjs.sha256"; then
    log "failed to download sha256 for ${version}"
    rm -rf "${release_dir}"
    continue
  fi

  curl -fsSL "${base_url}/changelog.json" -o "${release_dir}/changelog.json" 2>/dev/null \
    || echo '{}' > "${release_dir}/changelog.json"

  # Verify SHA256
  expected_hash="$(cut -d ' ' -f1 "${release_dir}/swarm-agent.cjs.sha256")"
  actual_hash="$(sha256sum "${release_dir}/swarm-agent.cjs.tmp" | cut -d ' ' -f1)"

  if [[ "${expected_hash}" != "${actual_hash}" ]]; then
    log "SHA256 mismatch for ${version}: expected=${expected_hash} actual=${actual_hash}"
    rm -rf "${release_dir}"
    continue
  fi

  mv "${release_dir}/swarm-agent.cjs.tmp" "${release_dir}/swarm-agent.cjs"
  log "downloaded and verified ${version}"
done

# --- Compute total downtime across all pending versions ---

LATEST_VERSION="${VERSIONS[-1]}"
TOTAL_DOWNTIME=0

for version in "${VERSIONS[@]}"; do
  changelog_path="${RELEASES_DIR}/${version}/changelog.json"
  if [[ -f "${changelog_path}" ]]; then
    version_downtime=$(python3 -c "
import json
try:
    data = json.load(open('${changelog_path}'))
    total = 0
    if data.get('version') == '${version}':
        for c in data.get('changes', []):
            if c.get('phase') == 'migrate':
                total += c.get('downtimeMinutes', 0)
    print(total)
except:
    print(0)
" 2>/dev/null || echo 0)
    TOTAL_DOWNTIME=$((TOTAL_DOWNTIME + version_downtime))
  fi
done

log "total downtime for upgrade path: ${TOTAL_DOWNTIME} minutes"

# --- Build combined changelog ---

COMBINED_CHANGELOG="["
first=true
for version in "${VERSIONS[@]}"; do
  changelog_path="${RELEASES_DIR}/${version}/changelog.json"
  if [[ -f "${changelog_path}" ]]; then
    version_entry=$(python3 -c "
import json
try:
    data = json.load(open('${changelog_path}'))
    if data.get('version') == '${version}':
        print(json.dumps(data))
except:
    pass
" 2>/dev/null || echo "")
    if [[ -n "${version_entry}" ]]; then
      if [[ "${first}" != "true" ]]; then
        COMBINED_CHANGELOG="${COMBINED_CHANGELOG},"
      fi
      COMBINED_CHANGELOG="${COMBINED_CHANGELOG}${version_entry}"
      first=false
    fi
  fi
done
COMBINED_CHANGELOG="${COMBINED_CHANGELOG}]"

# --- Check for approved upgrade with scheduled time ---

if [[ -f "${UPGRADE_APPROVED}" ]]; then
  approved_target=$(python3 -c "import json; d=json.load(open('${UPGRADE_APPROVED}')); print(d.get('target',''))" 2>/dev/null || echo "")
  scheduled_at=$(python3 -c "import json; d=json.load(open('${UPGRADE_APPROVED}')); print(d.get('scheduled_at',''))" 2>/dev/null || echo "")

  if [[ "${approved_target}" == "${LATEST_VERSION}" && -n "${scheduled_at}" ]]; then
    scheduled_epoch=$(date -d "${scheduled_at}" +%s 2>/dev/null || echo 0)
    now_epoch=$(date +%s)

    if (( scheduled_epoch > 0 && now_epoch >= scheduled_epoch )); then
      log "approved upgrade to ${LATEST_VERSION} is due (scheduled_at=${scheduled_at}); swapping binary"
      swap_and_restart "${LATEST_VERSION}"
      exit 0
    elif (( scheduled_epoch > 0 && now_epoch < scheduled_epoch )); then
      log "approved upgrade to ${LATEST_VERSION} scheduled for ${scheduled_at}; waiting"
      exit 0
    else
      log "approved upgrade has invalid scheduled_at='${scheduled_at}'; waiting for corrected schedule"
      exit 0
    fi
  fi
fi

# --- Decision: zero-downtime vs downtime ---

if (( TOTAL_DOWNTIME == 0 )); then
  log "zero-downtime upgrade to ${LATEST_VERSION}; swapping binary"
  swap_and_restart "${LATEST_VERSION}"
else
  log "downtime upgrade to ${LATEST_VERSION} (${TOTAL_DOWNTIME} min); writing upgrade-available.json"
  cat > "${UPGRADE_AVAILABLE}" <<AVAIL
{
  "current": "${CURRENT_VERSION}",
  "target": "${LATEST_VERSION}",
  "total_downtime_minutes": ${TOTAL_DOWNTIME},
  "changelog": ${COMBINED_CHANGELOG},
  "detected_at": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
}
AVAIL
fi

exit 0
