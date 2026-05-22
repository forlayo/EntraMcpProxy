#!/usr/bin/env bash
# End-to-end smoke test for the deployed EntraMcpProxy
#
# Authenticates a real user via Entra Device Code flow, then exercises the full
# MCP protocol against the deployed proxy.
#
# Prerequisites: bash, curl, jq
#
# Usage:
#   ./test-mcp.sh \
#       --tenant-id  <guid> \
#       --client-id  <guid> \
#       --proxy-url  https://aca-entra-mcp-proxy-devel.whitemoss-f4f610a7.northeurope.azurecontainerapps.io
#
#   # Specific tool with arguments:
#   ./test-mcp.sh \
#       --tenant-id  <guid> \
#       --client-id  <guid> \
#       --proxy-url  https://... \
#       --tool-name  azdevops__list_projects \
#       --tool-args  '{}'

set -euo pipefail

# ── ANSI colour helpers ────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
RESET='\033[0m'

green()  { printf "${GREEN}%s${RESET}\n"  "$*"; }
yellow() { printf "${YELLOW}%s${RESET}\n" "$*"; }
cyan()   { printf "${CYAN}%s${RESET}\n"   "$*"; }
red()    { printf "${RED}%s${RESET}\n"    "$*"; }
bold()   { printf "${WHITE}%s${RESET}\n"  "$*"; }

step() {
    printf "\n${CYAN}── Step %s: %s ──────────────────────────────────────────────${RESET}\n" "$1" "$2"
}

fail() {
    local msg="$1"
    local hint="${2:-}"
    printf "\n${RED}FAILED: %s${RESET}\n" "$msg"
    if [[ -n "$hint" ]]; then
        printf "${YELLOW}  Hint: %s${RESET}\n" "$hint"
    fi
    exit 1
}

# ── Parameter parsing ──────────────────────────────────────────────────────────

TENANT_ID=""
CLIENT_ID=""
PROXY_URL=""
TOOL_NAME=""
TOOL_ARGS="{}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tenant-id)  TENANT_ID="$2";  shift 2 ;;
        --client-id)  CLIENT_ID="$2";  shift 2 ;;
        --proxy-url)  PROXY_URL="$2";  shift 2 ;;
        --tool-name)  TOOL_NAME="$2";  shift 2 ;;
        --tool-args)  TOOL_ARGS="$2";  shift 2 ;;
        *)
            printf "${RED}Unknown parameter: %s${RESET}\n" "$1"
            printf "Usage: %s --tenant-id <guid> --client-id <guid> --proxy-url <url> [--tool-name <name>] [--tool-args '{}']\n" "$0"
            exit 1
            ;;
    esac
done

# Validate required parameters
[[ -z "$TENANT_ID" ]] && fail "--tenant-id is required"
[[ -z "$CLIENT_ID" ]] && fail "--client-id is required"
[[ -z "$PROXY_URL" ]] && fail "--proxy-url is required"

# Verify dependencies
for cmd in curl jq; do
    command -v "$cmd" &>/dev/null || fail "Required command not found: $cmd" "Install $cmd and re-run."
done

PROXY_URL="${PROXY_URL%/}"   # strip trailing slash

# ── Timing helpers ─────────────────────────────────────────────────────────────

SCRIPT_START=$(date +%s%3N 2>/dev/null || date +%s)

elapsed_ms() {
    local now
    now=$(date +%s%3N 2>/dev/null || echo 0)
    echo $((now - SCRIPT_START))
}

# ── Summary tracking ───────────────────────────────────────────────────────────

declare -a SUMMARY_KEYS=()
declare -A SUMMARY_PASS=()
declare -A SUMMARY_DETAIL=()

mark_pass() {
    local key="$1" detail="$2"
    SUMMARY_KEYS+=("$key")
    SUMMARY_PASS["$key"]="true"
    SUMMARY_DETAIL["$key"]="$detail"
}

mark_fail() {
    local key="$1" detail="$2"
    SUMMARY_KEYS+=("$key")
    SUMMARY_PASS["$key"]="false"
    SUMMARY_DETAIL["$key"]="$detail"
}

# ── Utility: parse MCP response (SSE or JSON) ─────────────────────────────────

parse_mcp_response() {
    local body="$1"
    local content_type="$2"

    if [[ "$content_type" == *"text/event-stream"* ]]; then
        # Extract the first "data: {...}" line
        echo "$body" | grep '^data: {' | head -1 | sed 's/^data: //'
    else
        echo "$body"
    fi
}

# ── Utility: decode JWT payload ────────────────────────────────────────────────

decode_jwt_payload() {
    local token="$1"
    local payload
    payload=$(echo "$token" | cut -d'.' -f2)
    # Pad base64url to standard base64
    local padded="$payload"
    local pad_count=$(( (4 - ${#padded} % 4) % 4 ))
    for ((i=0; i<pad_count; i++)); do padded="${padded}="; done
    # Translate base64url → base64 then decode
    echo "$padded" | tr '_-' '/+' | base64 -d 2>/dev/null || echo '{}'
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 — Pre-flight checks
# ══════════════════════════════════════════════════════════════════════════════

step "1" "Pre-flight checks"

# 1a. Health check
t1=$(date +%s%3N 2>/dev/null || echo 0)
health_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 "$PROXY_URL/api/healthz")
t1_elapsed=$(( $(date +%s%3N 2>/dev/null || echo 0) - t1 ))

if [[ "$health_status" != "200" ]]; then
    mark_fail "Proxy healthz" "HTTP $health_status"
    fail "Healthz returned $health_status" "Check the proxy is deployed and the container app is running."
fi
green "  [OK] /api/healthz → 200 (${t1_elapsed}ms)"
mark_pass "Proxy healthz" "200 OK"

# 1b. OAuth discovery doc
t2=$(date +%s%3N 2>/dev/null || echo 0)
discovery_body=$(curl -s --max-time 15 "$PROXY_URL/.well-known/openid-configuration") || \
    fail "Could not fetch OAuth discovery doc"
t2_elapsed=$(( $(date +%s%3N 2>/dev/null || echo 0) - t2 ))

expected_scope="api://$CLIENT_ID/user_impersonation"
if ! echo "$discovery_body" | jq -e --arg s "$expected_scope" '.scopes_supported | index($s) != null' &>/dev/null; then
    mark_fail "OAuth discovery doc" "scope '$expected_scope' not in scopes_supported"
    fail "Discovery doc does not advertise scope '$expected_scope'." \
         "Verify --client-id is correct and the proxy was deployed with the right EntraId:ClientId."
fi
green "  [OK] /.well-known/openid-configuration → scope '$expected_scope' present (${t2_elapsed}ms)"
mark_pass "OAuth discovery doc" "scope present"

# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 — Device Code flow against Entra
# ══════════════════════════════════════════════════════════════════════════════

step "2" "Device Code OAuth (Entra)"

SCOPE="api://$CLIENT_ID/user_impersonation offline_access openid profile"
DEVICE_CODE_ENDPOINT="https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/devicecode"
TOKEN_ENDPOINT="https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token"

t3=$(date +%s%3N 2>/dev/null || echo 0)
dc_response=$(curl -s -w "\n%{http_code}" --max-time 30 \
    -X POST "$DEVICE_CODE_ENDPOINT" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "client_id=$CLIENT_ID" \
    --data-urlencode "scope=$SCOPE")
t3_elapsed=$(( $(date +%s%3N 2>/dev/null || echo 0) - t3 ))

dc_http_status=$(echo "$dc_response" | tail -1)
dc_body=$(echo "$dc_response" | head -n -1)

if [[ "$dc_http_status" != "200" ]]; then
    err_code=$(echo "$dc_body" | jq -r '.error // "unknown"')
    mark_fail "Entra device-code auth" "HTTP $dc_http_status ($err_code)"
    if [[ "$err_code" == "invalid_scope" ]] || echo "$dc_body" | grep -q "AADSTS70011"; then
        fail "Device code request failed: invalid scope (HTTP $dc_http_status)" \
             "Ensure the proxy app registration exposes scope 'user_impersonation' under api://$CLIENT_ID."
    elif echo "$dc_body" | grep -q "AADSTS700016"; then
        fail "Device code request failed: client not found (HTTP $dc_http_status)" \
             "Check --tenant-id and --client-id are correct."
    else
        fail "Device code request failed (HTTP $dc_http_status): $(echo "$dc_body" | jq -r '.error_description // .error // "unknown"')"
    fi
fi

DEVICE_CODE=$(echo "$dc_body" | jq -r '.device_code')
USER_CODE=$(echo "$dc_body" | jq -r '.user_code')
VERIFICATION_URI=$(echo "$dc_body" | jq -r '.verification_uri')
VERIFICATION_URI_COMPLETE=$(echo "$dc_body" | jq -r '.verification_uri_complete // empty')
POLL_INTERVAL=$(echo "$dc_body" | jq -r '.interval // 5')
EXPIRES_IN=$(echo "$dc_body" | jq -r '.expires_in // 900')

# Prominent action box
printf "\n"
printf "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${RESET}\n"
printf "${YELLOW}  ║  ACTION REQUIRED — sign in to authenticate                   ║${RESET}\n"
printf "${YELLOW}  ║                                                              ║${RESET}\n"
printf "${YELLOW}  ║  Open in your browser:                                       ║${RESET}\n"
printf "${YELLOW}  ║    %-52s║${RESET}\n" "$VERIFICATION_URI"
printf "${YELLOW}  ║                                                              ║${RESET}\n"
printf "${YELLOW}  ║  Enter this code:                                            ║${RESET}\n"
printf "${CYAN}  ║    %-52s${YELLOW}║${RESET}\n" "$USER_CODE"
printf "${YELLOW}  ║                                                              ║${RESET}\n"
printf "${YELLOW}  ║  Waiting for sign-in (expires in %s s)...              ║${RESET}\n" "$EXPIRES_IN"
printf "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${RESET}\n"
printf "\n"

# Try to auto-open browser
OPEN_URL="${VERIFICATION_URI_COMPLETE:-$VERIFICATION_URI}"
if command -v xdg-open &>/dev/null; then
    xdg-open "$OPEN_URL" 2>/dev/null && yellow "  (Browser launched automatically with the code pre-filled)" || true
elif command -v open &>/dev/null; then
    open "$OPEN_URL" 2>/dev/null && yellow "  (Browser launched automatically with the code pre-filled)" || true
else
    yellow "  Could not launch browser automatically. Open the URL above manually."
fi

# Poll for the token
auth_start=$(date +%s)
ACCESS_TOKEN=""

while true; do
    sleep "$POLL_INTERVAL"

    now=$(date +%s)
    auth_elapsed=$(( now - auth_start ))

    poll_response=$(curl -s -w "\n%{http_code}" --max-time 30 \
        -X POST "$TOKEN_ENDPOINT" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
        --data-urlencode "device_code=$DEVICE_CODE" \
        --data-urlencode "client_id=$CLIENT_ID")

    poll_status=$(echo "$poll_response" | tail -1)
    poll_body=$(echo "$poll_response" | head -n -1)
    poll_err=$(echo "$poll_body" | jq -r '.error // empty')

    if [[ "$poll_status" == "200" ]] && [[ -z "$poll_err" ]]; then
        ACCESS_TOKEN=$(echo "$poll_body" | jq -r '.access_token')
        break
    fi

    case "$poll_err" in
        "authorization_pending")
            printf "  ... waiting (%ds elapsed)\r" "$auth_elapsed"
            ;;
        "slow_down")
            POLL_INTERVAL=$(( POLL_INTERVAL * 2 ))
            yellow "  Rate limited — slowing poll to every ${POLL_INTERVAL}s"
            ;;
        "access_denied")
            mark_fail "Entra device-code auth" "access_denied"
            fail "User cancelled or denied the sign-in request."
            ;;
        "expired_token")
            mark_fail "Entra device-code auth" "expired_token"
            fail "The device code expired before sign-in completed (ran for ${auth_elapsed}s)." \
                 "Re-run the script and complete sign-in within $EXPIRES_IN seconds."
            ;;
        *)
            mark_fail "Entra device-code auth" "error=$poll_err"
            fail "Token request failed (error=$poll_err): $(echo "$poll_body" | jq -r '.error_description // .error // "unknown"')"
            ;;
    esac
done

printf "\n"

if [[ -z "$ACCESS_TOKEN" ]]; then
    mark_fail "Entra device-code auth" "no access_token in response"
    fail "Token response did not contain an access_token."
fi

# Decode and display JWT claims
jwt_payload=$(decode_jwt_payload "$ACCESS_TOKEN")
jwt_upn=$(echo "$jwt_payload" | jq -r '.upn // .preferred_username // .email // "unknown"')
jwt_oid=$(echo "$jwt_payload" | jq -r '.oid // "n/a"')
jwt_tid=$(echo "$jwt_payload" | jq -r '.tid // "n/a"')
jwt_aud=$(echo "$jwt_payload" | jq -r '.aud // "n/a"')
jwt_scp=$(echo "$jwt_payload" | jq -r '.scp // "n/a"')
jwt_exp=$(echo "$jwt_payload" | jq -r '.exp // "n/a"')
if [[ "$jwt_exp" != "n/a" ]] && command -v date &>/dev/null; then
    jwt_exp_fmt=$(date -d "@$jwt_exp" "+%Y-%m-%d %H:%M:%S UTC" 2>/dev/null || date -r "$jwt_exp" "+%Y-%m-%d %H:%M:%S UTC" 2>/dev/null || echo "$jwt_exp")
else
    jwt_exp_fmt="$jwt_exp"
fi

auth_total=$(( $(date +%s) - auth_start ))

green "  [OK] Authentication successful (${auth_total}s total auth time)"
printf "       User    : %s\n" "$jwt_upn"
printf "       OID     : %s\n" "$jwt_oid"
printf "       TID     : %s\n" "$jwt_tid"
printf "       Audience: %s\n" "$jwt_aud"
printf "       Scope   : %s\n" "$jwt_scp"
printf "       Expires : %s\n" "$jwt_exp_fmt"

mark_pass "Entra device-code auth" "$jwt_upn"

# ══════════════════════════════════════════════════════════════════════════════
# STEP 3 — MCP initialize
# ══════════════════════════════════════════════════════════════════════════════

step "3" "MCP initialize"

MCP_URL="$PROXY_URL/mcp"
PROTOCOL_VER="2025-06-18"

init_body=$(jq -cn \
    --arg pv "$PROTOCOL_VER" \
    '{jsonrpc:"2.0",id:1,method:"initialize",params:{protocolVersion:$pv,capabilities:{},clientInfo:{name:"test-mcp-script",version:"1.0.0"}}}')

t4=$(date +%s%3N 2>/dev/null || echo 0)
init_response=$(curl -s -D - --max-time 30 \
    -X POST "$MCP_URL" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -H "MCP-Protocol-Version: $PROTOCOL_VER" \
    -d "$init_body")
init_curl_exit=$?
t4_elapsed=$(( $(date +%s%3N 2>/dev/null || echo 0) - t4 ))

if [[ $init_curl_exit -ne 0 ]]; then
    mark_fail "MCP initialize" "curl error $init_curl_exit"
    fail "curl failed to connect to $MCP_URL (exit $init_curl_exit)" \
         "Confirm the proxy URL is correct and the container app is running."
fi

# Split headers from body (curl -D -)
init_headers=$(echo "$init_response" | awk '/^\r?$/{exit} {print}')
init_body_raw=$(echo "$init_response" | awk 'found{print} /^\r?$/{found=1}')

# Extract HTTP status
init_http_status=$(echo "$init_headers" | head -1 | grep -oP '(?<=HTTP/\S+ )\d+' || echo "0")

if [[ "$init_http_status" == "401" ]]; then
    mark_fail "MCP initialize" "HTTP 401"
    fail "MCP /mcp returned 401 Unauthorized." \
         "Token rejected by proxy — verify the access token audience ('aud' claim) is 'api://$CLIENT_ID' or '$CLIENT_ID'."
elif [[ "$init_http_status" == "403" ]]; then
    mark_fail "MCP initialize" "HTTP 403"
    fail "MCP /mcp returned 403 Forbidden." \
         "The token is valid but the user lacks authorization. Check group membership and DownstreamAuthorizationFilter config."
elif [[ "$init_http_status" != "200" ]]; then
    mark_fail "MCP initialize" "HTTP $init_http_status"
    fail "MCP initialize returned HTTP $init_http_status."
fi

# Extract Mcp-Session-Id (case-insensitive)
SESSION_ID=$(echo "$init_headers" | grep -i '^Mcp-Session-Id:' | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r\n')

if [[ -z "$SESSION_ID" ]]; then
    mark_fail "MCP initialize" "Mcp-Session-Id header missing"
    fail "The initialize response did not include an Mcp-Session-Id header." \
         "The MCP SDK on the proxy may not have initialized correctly. Check proxy logs."
fi

# Parse response (SSE or JSON)
init_ct=$(echo "$init_headers" | grep -i '^Content-Type:' | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r\n')
init_json=$(parse_mcp_response "$init_body_raw" "$init_ct")

if [[ -z "$init_json" ]]; then
    mark_fail "MCP initialize" "could not parse response"
    fail "Could not parse the MCP initialize response (Content-Type: $init_ct)."
fi

rpc_error=$(echo "$init_json" | jq -r '.error.message // empty')
if [[ -n "$rpc_error" ]]; then
    mark_fail "MCP initialize" "JSON-RPC error: $rpc_error"
    fail "MCP initialize returned a JSON-RPC error: $rpc_error"
fi

server_proto=$(echo "$init_json" | jq -r '.result.protocolVersion // "n/a"')
server_name=$(echo "$init_json" | jq -r '.result.serverInfo.name // "n/a"')
server_ver=$(echo "$init_json" | jq -r '.result.serverInfo.version // "n/a"')
server_caps=$(echo "$init_json" | jq -c '.result.capabilities // {}')

green "  [OK] MCP initialize → session=$SESSION_ID (${t4_elapsed}ms)"
printf "       Protocol : %s\n" "$server_proto"
printf "       Server   : %s v%s\n" "$server_name" "$server_ver"
printf "       Caps     : %s\n" "$server_caps"

mark_pass "MCP initialize" "session=$SESSION_ID, protocol=$server_proto"

# ══════════════════════════════════════════════════════════════════════════════
# STEP 4 — notifications/initialized
# ══════════════════════════════════════════════════════════════════════════════

step "4" "Send notifications/initialized"

notif_body='{"jsonrpc":"2.0","method":"notifications/initialized"}'

t5=$(date +%s%3N 2>/dev/null || echo 0)
notif_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
    -X POST "$MCP_URL" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -H "Mcp-Session-Id: $SESSION_ID" \
    -H "MCP-Protocol-Version: $PROTOCOL_VER" \
    -d "$notif_body" 2>/dev/null) || notif_status="0"
t5_elapsed=$(( $(date +%s%3N 2>/dev/null || echo 0) - t5 ))

if [[ "$notif_status" == "202" ]] || [[ "$notif_status" == "200" ]]; then
    green "  [OK] notifications/initialized → $notif_status (${t5_elapsed}ms)"
elif [[ "$notif_status" == "405" ]]; then
    yellow "  [NOTE] notifications/initialized → 405 Method Not Allowed (${t5_elapsed}ms) — continuing"
else
    yellow "  [WARN] notifications/initialized returned $notif_status (expected 202) — continuing"
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 5 — tools/list
# ══════════════════════════════════════════════════════════════════════════════

step "5" "tools/list"

list_body='{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

t6=$(date +%s%3N 2>/dev/null || echo 0)
list_response=$(curl -s -D - --max-time 30 \
    -X POST "$MCP_URL" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -H "Mcp-Session-Id: $SESSION_ID" \
    -H "MCP-Protocol-Version: $PROTOCOL_VER" \
    -d "$list_body")
list_curl_exit=$?
t6_elapsed=$(( $(date +%s%3N 2>/dev/null || echo 0) - t6 ))

if [[ $list_curl_exit -ne 0 ]]; then
    mark_fail "MCP tools/list" "curl error $list_curl_exit"
    fail "curl failed during tools/list (exit $list_curl_exit)"
fi

list_headers=$(echo "$list_response" | awk '/^\r?$/{exit} {print}')
list_body_raw=$(echo "$list_response" | awk 'found{print} /^\r?$/{found=1}')
list_http_status=$(echo "$list_headers" | head -1 | grep -oP '(?<=HTTP/\S+ )\d+' || echo "0")

if [[ "$list_http_status" != "200" ]]; then
    mark_fail "MCP tools/list" "HTTP $list_http_status"
    fail "tools/list returned HTTP $list_http_status"
fi

list_ct=$(echo "$list_headers" | grep -i '^Content-Type:' | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r\n')
list_json=$(parse_mcp_response "$list_body_raw" "$list_ct")

if [[ -z "$list_json" ]]; then
    mark_fail "MCP tools/list" "could not parse response"
    fail "Could not parse tools/list response."
fi

rpc_error=$(echo "$list_json" | jq -r '.error.message // empty')
if [[ -n "$rpc_error" ]]; then
    mark_fail "MCP tools/list" "JSON-RPC error: $rpc_error"
    fail "tools/list returned a JSON-RPC error: $rpc_error"
fi

tool_count=$(echo "$list_json" | jq '.result.tools | length')
green "  [OK] tools/list → $tool_count tool(s) (${t6_elapsed}ms)"

# Print tool table
provenance_present=false
if [[ "$tool_count" -gt 0 ]]; then
    printf "\n"
    printf "  %-45s %s\n" "TOOL NAME" "DESCRIPTION (first 60 chars)"
    printf "  %-45s %s\n" "$(printf '%0.s-' {1..45})" "$(printf '%0.s-' {1..60})"
    while IFS= read -r line; do
        tool_name_col=$(echo "$line" | jq -r '.name')
        tool_desc_col=$(echo "$line" | jq -r '.description // ""')
        if [[ "$tool_desc_col" == \[Source:* ]]; then
            provenance_present=true
        fi
        short_desc="${tool_desc_col:0:60}"
        [[ ${#tool_desc_col} -gt 60 ]] && short_desc="${tool_desc_col:0:57}..."
        printf "  %-45s %s\n" "$tool_name_col" "$short_desc"
    done < <(echo "$list_json" | jq -c '.result.tools[]')
    printf "\n"
fi

if [[ "$provenance_present" == "true" ]]; then
    green "  [OK] Provenance prefix '[Source: ...]' detected in tool descriptions (Phase 9 N5)"
    mark_pass "MCP tools/list" "$tool_count tools, provenance prefix present"
else
    yellow "  [NOTE] Provenance prefix '[Source: ...]' not detected in tool descriptions."
    yellow "         This may be expected if the downstream descriptions don't include it."
    mark_pass "MCP tools/list" "$tool_count tools advertised"
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 6 — tools/call
# ══════════════════════════════════════════════════════════════════════════════

step "6" "tools/call"

SELECTED_TOOL=""

if [[ -n "$TOOL_NAME" ]]; then
    SELECTED_TOOL="$TOOL_NAME"
    printf "  Using specified tool: %s\n" "$SELECTED_TOOL"
elif [[ "$tool_count" -eq 0 ]]; then
    yellow "  [SKIP] No tools available — skipping tools/call"
    mark_pass "MCP tools/call" "skipped (no tools)"
else
    # Interactive selection using bash 'select' or default to first
    if [[ -t 0 ]]; then
        # Interactive terminal
        printf "\n  Available tools:\n"
        mapfile -t tool_names < <(echo "$list_json" | jq -r '.result.tools[].name')
        printf "\n"
        PS3="  Pick a tool [1-${#tool_names[@]}] (default 1): "
        select choice in "${tool_names[@]}"; do
            if [[ -n "$choice" ]]; then
                SELECTED_TOOL="$choice"
                break
            elif [[ -z "$REPLY" ]] || [[ "$REPLY" == "1" ]]; then
                SELECTED_TOOL="${tool_names[0]}"
                break
            fi
        done
    else
        # Non-interactive: use first tool
        SELECTED_TOOL=$(echo "$list_json" | jq -r '.result.tools[0].name')
        printf "  Non-interactive mode — using first tool: %s\n" "$SELECTED_TOOL"
    fi
fi

if [[ -n "$SELECTED_TOOL" ]]; then
    # Validate tool args is valid JSON
    if ! echo "$TOOL_ARGS" | jq . &>/dev/null; then
        yellow "  [WARN] --tool-args is not valid JSON — using empty object"
        TOOL_ARGS="{}"
    fi

    call_body=$(jq -cn \
        --arg name "$SELECTED_TOOL" \
        --argjson args "$TOOL_ARGS" \
        '{jsonrpc:"2.0",id:3,method:"tools/call",params:{name:$name,arguments:$args}}')

    t7=$(date +%s%3N 2>/dev/null || echo 0)
    call_response=$(curl -s -D - --max-time 60 \
        -X POST "$MCP_URL" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -H "Mcp-Session-Id: $SESSION_ID" \
        -H "MCP-Protocol-Version: $PROTOCOL_VER" \
        -d "$call_body")
    call_curl_exit=$?
    t7_elapsed=$(( $(date +%s%3N 2>/dev/null || echo 0) - t7 ))

    if [[ $call_curl_exit -ne 0 ]]; then
        mark_fail "MCP tools/call" "curl error $call_curl_exit"
        fail "curl failed during tools/call (exit $call_curl_exit)"
    fi

    call_headers=$(echo "$call_response" | awk '/^\r?$/{exit} {print}')
    call_body_raw=$(echo "$call_response" | awk 'found{print} /^\r?$/{found=1}')
    call_http_status=$(echo "$call_headers" | head -1 | grep -oP '(?<=HTTP/\S+ )\d+' || echo "0")

    if [[ "$call_http_status" == "401" ]]; then
        mark_fail "MCP tools/call" "HTTP 401"
        fail "tools/call returned 401 — token may have expired during the test." "Re-run the script."
    elif [[ "$call_http_status" != "200" ]]; then
        mark_fail "MCP tools/call" "HTTP $call_http_status"
        fail "tools/call returned HTTP $call_http_status"
    fi

    call_ct=$(echo "$call_headers" | grep -i '^Content-Type:' | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r\n')
    call_json=$(parse_mcp_response "$call_body_raw" "$call_ct")

    if [[ -z "$call_json" ]]; then
        mark_fail "MCP tools/call" "could not parse response"
        fail "Could not parse tools/call response."
    fi

    rpc_error=$(echo "$call_json" | jq -r '.error.message // empty')
    if [[ -n "$rpc_error" ]]; then
        mark_fail "MCP tools/call" "JSON-RPC error: $rpc_error"
        fail "tools/call returned a JSON-RPC error: $rpc_error"
    fi

    content_count=$(echo "$call_json" | jq '.result.content | length')
    is_error=$(echo "$call_json" | jq -r '.result.isError // false')

    green "  [OK] tools/call → $SELECTED_TOOL (${t7_elapsed}ms)"

    downstream_wrapping=false
    if [[ "$content_count" -gt 0 ]]; then
        printf "\n  Content blocks (%s):\n" "$content_count"
        while IFS= read -r block; do
            block_type=$(echo "$block" | jq -r '.type')
            block_text=$(echo "$block" | jq -r '.text // ""')
            if echo "$block_text" | grep -q '<downstream-content'; then
                downstream_wrapping=true
            fi
            preview="${block_text:0:200}"
            [[ ${#block_text} -gt 200 ]] && preview="${block_text:0:197}..."
            printf "  ── type=%s ──\n" "$block_type"
            printf "%s\n" "$preview"
        done < <(echo "$call_json" | jq -c '.result.content[]')
        printf "\n"
    fi

    if [[ "$is_error" == "true" ]]; then
        yellow "  [NOTE] isError=true in response. If this mentions permissions, the user may lack"
        yellow "         access to that ADO resource — this is not a proxy bug."
    fi

    if [[ "$downstream_wrapping" == "true" ]]; then
        green "  [OK] <downstream-content> marker present in result (Phase 10 N11 wrapping verified)"
        mark_pass "MCP tools/call" "$SELECTED_TOOL → content received"
        mark_pass "Provenance wrapping" "<downstream-content> marker present"
    else
        yellow "  [NOTE] <downstream-content> marker not found. This may be expected if"
        yellow "         ProvenanceStyle is not 'Full' in the proxy configuration."
        mark_pass "MCP tools/call" "$SELECTED_TOOL → content received (no wrapping tag)"
        mark_fail "Provenance wrapping" "<downstream-content> not found (check ProvenanceStyle config)"
    fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 7 — DELETE session
# ══════════════════════════════════════════════════════════════════════════════

step "7" "DELETE session"

t8=$(date +%s%3N 2>/dev/null || echo 0)
del_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
    -X DELETE "$MCP_URL" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Mcp-Session-Id: $SESSION_ID" 2>/dev/null) || del_status="0"
t8_elapsed=$(( $(date +%s%3N 2>/dev/null || echo 0) - t8 ))

if [[ "$del_status" == "200" ]] || [[ "$del_status" == "204" ]]; then
    green "  [OK] DELETE session → $del_status (${t8_elapsed}ms)"
elif [[ "$del_status" == "405" ]]; then
    yellow "  [OK/NOTE] DELETE returned 405 (server does not allow client-initiated session termination — expected) (${t8_elapsed}ms)"
else
    yellow "  [WARN] DELETE session returned $del_status — continuing (${t8_elapsed}ms)"
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 8 — Summary table
# ══════════════════════════════════════════════════════════════════════════════

printf "\n"
printf "${CYAN}═══════════════════════════════════════════════════════════════${RESET}\n"
printf "${CYAN} RESULT${RESET}\n"
printf "${CYAN}═══════════════════════════════════════════════════════════════${RESET}\n"

all_passed=true
for key in "${SUMMARY_KEYS[@]}"; do
    pass="${SUMMARY_PASS[$key]}"
    detail="${SUMMARY_DETAIL[$key]}"
    if [[ "$pass" == "true" ]]; then
        printf "${GREEN} [PASS] %-30s %s${RESET}\n" "$key" "$detail"
    else
        printf "${RED} [FAIL] %-30s %s${RESET}\n" "$key" "$detail"
        all_passed=false
    fi
done

printf "${CYAN}═══════════════════════════════════════════════════════════════${RESET}\n"

total_elapsed=$(elapsed_ms)
if [[ "$all_passed" == "true" ]]; then
    printf "${GREEN} ALL CHECKS PASSED — the proxy is end-to-end functional.${RESET}\n"
    printf "${GREEN} Total elapsed: %sms${RESET}\n" "$total_elapsed"
else
    printf "${RED} SOME CHECKS FAILED — see details above.${RESET}\n"
    printf "${RED} Total elapsed: %sms${RESET}\n" "$total_elapsed"
fi

printf "${CYAN}═══════════════════════════════════════════════════════════════${RESET}\n"
printf "\n"

[[ "$all_passed" == "true" ]]
