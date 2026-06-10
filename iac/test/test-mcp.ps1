#!/usr/bin/env pwsh
<#
.SYNOPSIS
    End-to-end smoke test for the deployed EntraMcpProxy.

.DESCRIPTION
    Authenticates a real user via Entra Device Code flow (no redirect_uri needed),
    then exercises the full MCP protocol against the deployed proxy:

      1. Pre-flight: /api/healthz + /.well-known/openid-configuration
      2. Device Code OAuth — user opens browser, enters code, signs in (MFA supported)
      3. MCP initialize  -> detects stateful or stateless transport
      4. notifications/initialized (per MCP spec)
      5. tools/list      -> confirms provenance prefix '[Source: downstream=...]'
      6. tools/call      -> confirms <downstream-content> wrapping
      7. DELETE session when stateful
      8. Summary table

    This validates every security control in the full call path without needing claude.ai.
    Device Code is the sanctioned interactive-CLI flow -- works with MFA and Conditional
    Access because the user authenticates directly against Entra.

    Compatible with Windows PowerShell 5.1 and PowerShell 7+.

.PARAMETER TenantId
    The Entra tenant GUID (e.g. xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).

.PARAMETER ClientId
    The proxy app registration client GUID.

.PARAMETER ProxyUrl
    The deployed proxy FQDN, e.g. https://aca-entra-mcp-proxy-devel.whitemoss-f4f610a7.northeurope.azurecontainerapps.io

.PARAMETER ToolName
    Optional. If set, calls this specific tool (e.g. azdevops__list_projects).
    Otherwise lists tools and prompts the user to pick one.

.PARAMETER ToolArgs
    Optional. JSON string with tool arguments, e.g. '{"projectName":"my-project"}'.
    Defaults to '{}' if not supplied.

.EXAMPLE
    # Interactive run -- picks the first available tool
    .\test-mcp.ps1 `
        -TenantId  xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx `
        -ClientId  yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy `
        -ProxyUrl  https://aca-entra-mcp-proxy-devel.whitemoss-f4f610a7.northeurope.azurecontainerapps.io

.EXAMPLE
    # Specific tool with arguments
    .\test-mcp.ps1 `
        -TenantId  xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx `
        -ClientId  yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy `
        -ProxyUrl  https://aca-entra-mcp-proxy-devel.whitemoss-f4f610a7.northeurope.azurecontainerapps.io `
        -ToolName  azdevops__list_projects `
        -ToolArgs  '{}'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string] $TenantId,

    [Parameter(Mandatory=$true)]
    [string] $ClientId,

    [Parameter(Mandatory=$true)]
    [string] $ProxyUrl,

    [Parameter(Mandatory=$false)]
    [string] $ToolName = "",

    [Parameter(Mandatory=$false)]
    [string] $ToolArgs = "{}"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Compat helper: PS 5.1 does not have $IsWindows / $IsMacOS / $IsLinux ──────
if (-not (Test-Path variable:IsWindows)) { $IsWindows = $true  }
if (-not (Test-Path variable:IsMacOS))   { $IsMacOS   = $false }
if (-not (Test-Path variable:IsLinux))   { $IsLinux   = $false }

# ── Helper: null coalescing for PS 5.1 (no ?? operator) ────────────────────────
function Coalesce {
    param($a, $b)
    if ($null -ne $a -and $a -ne "") { return $a }
    return $b
}

# ── Colour helpers (degrade gracefully on PS 5.1 / non-interactive hosts) ──────

function Write-Green  { param($Msg) Write-Host $Msg -ForegroundColor Green  }
function Write-Yellow { param($Msg) Write-Host $Msg -ForegroundColor Yellow }
function Write-Cyan   { param($Msg) Write-Host $Msg -ForegroundColor Cyan   }
function Write-Red    { param($Msg) Write-Host $Msg -ForegroundColor Red    }

function Write-Step {
    param([string]$Num, [string]$Title)
    Write-Host ""
    Write-Cyan "-- Step ${Num}: $Title ----------------------------------------------------"
}

function Fail {
    param([string]$Msg, [string]$Hint = "")
    Write-Host ""
    Write-Red "FAILED: $Msg"
    if ($Hint -ne "") {
        Write-Yellow "  Hint: $Hint"
    }
    exit 1
}

# ── Utility: elapsed time ───────────────────────────────────────────────────────

$ScriptStart = [System.Diagnostics.Stopwatch]::StartNew()

function Elapsed {
    $ms = $ScriptStart.ElapsedMilliseconds
    if ($ms -lt 1000) { return "${ms}ms" }
    $s = [Math]::Round($ms / 1000, 1)
    return "${s}s"
}

# ── Utility: parse SSE or JSON response ────────────────────────────────────────
# The MCP SDK may respond with Content-Type: text/event-stream even for
# non-streaming requests.  This function handles both.

function Parse-McpResponse {
    param([string]$Body, [string]$ContentType)

    if ($ContentType -like "*text/event-stream*") {
        # SSE format: lines starting with "data: " contain JSON-RPC objects.
        foreach ($line in ($Body -split "`n")) {
            $line = $line.Trim()
            if ($line -match '^data:\s*(\{.+\})$') {
                return ($Matches[1] | ConvertFrom-Json)
            }
        }
        # No data line found
        return $null
    }
    else {
        # Plain JSON
        return ($Body | ConvertFrom-Json)
    }
}

# ── Utility: safe property access for PS 5.1 (no ?. operator) ─────────────────

function Get-Prop {
    param($Obj, [string]$Prop, $Default = "n/a")
    if ($null -eq $Obj) { return $Default }
    $val = $Obj.PSObject.Properties[$Prop]
    if ($null -eq $val -or $null -eq $val.Value) { return $Default }
    if ($val.Value -eq "") { return $Default }
    return $val.Value
}

# ── Utility: decode JWT payload ────────────────────────────────────────────────

function Decode-JwtPayload {
    param([string]$Token)

    $parts = $Token -split '\.'
    if ($parts.Count -lt 2) { return $null }

    $payload = $parts[1]
    # Pad base64url to standard base64
    $padded  = $payload -replace '-', '+' -replace '_', '/'
    switch ($padded.Length % 4) {
        2 { $padded += "==" }
        3 { $padded += "=" }
    }
    try {
        $bytes = [System.Convert]::FromBase64String($padded)
        $json  = [System.Text.Encoding]::UTF8.GetString($bytes)
        return ($json | ConvertFrom-Json)
    }
    catch {
        return $null
    }
}

# ── Utility: get HTTP status from WebException ─────────────────────────────────

function Get-ExceptionStatus {
    param($Err)
    try {
        $resp = $Err.Exception.Response
        if ($null -ne $resp) {
            # PS 7: HttpResponseMessage (.StatusCode is HttpStatusCode enum)
            # PS 5: HttpWebResponse (.StatusCode is HttpStatusCode enum)
            return [int]$resp.StatusCode
        }
    }
    catch {}
    return 0
}

# ── Summary tracking ───────────────────────────────────────────────────────────

# Use two parallel arrays (ordered dict values aren't stable in PS 5.1 hashtable)
$SummaryKeys   = New-Object System.Collections.Generic.List[string]
$SummaryPass   = @{}
$SummaryDetail = @{}

function Mark-Pass {
    param([string]$Key, [string]$Detail)
    $SummaryKeys.Add($Key)
    $SummaryPass[$Key]   = $true
    $SummaryDetail[$Key] = $Detail
}
function Mark-Fail {
    param([string]$Key, [string]$Detail)
    $SummaryKeys.Add($Key)
    $SummaryPass[$Key]   = $false
    $SummaryDetail[$Key] = $Detail
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 -- Pre-flight checks
# ══════════════════════════════════════════════════════════════════════════════

Write-Step "1" "Pre-flight checks"

$ProxyUrl = $ProxyUrl.TrimEnd('/')

# 1a. Health check
$t1 = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $healthResp = Invoke-WebRequest -Uri "$ProxyUrl/api/healthz" -Method GET `
                      -UseBasicParsing -ErrorAction Stop
    $t1.Stop()
    if ($healthResp.StatusCode -ne 200) {
        Mark-Fail "Proxy healthz" "$($healthResp.StatusCode)"
        Fail "Healthz returned $($healthResp.StatusCode)" `
             "Check the proxy is deployed and running."
    }
    Write-Green "  [OK] /api/healthz -> 200 ($($t1.ElapsedMilliseconds)ms)"
    Mark-Pass "Proxy healthz" "200 OK"
}
catch {
    $t1.Stop()
    Mark-Fail "Proxy healthz" "$_"
    Fail "Could not reach $ProxyUrl/api/healthz: $_" `
         "Confirm -ProxyUrl is correct and the container app is running."
}

# 1b. OAuth discovery doc
$t2 = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $discoveryResp = Invoke-RestMethod -Uri "$ProxyUrl/.well-known/openid-configuration" `
                         -Method GET -ErrorAction Stop
    $t2.Stop()
    $expectedScope = "api://$ClientId/user_impersonation"
    $scopesSupported = $discoveryResp.scopes_supported
    if ($scopesSupported -notcontains $expectedScope) {
        Mark-Fail "OAuth discovery doc" "scope '$expectedScope' not in scopes_supported"
        Fail "Discovery doc does not advertise scope '$expectedScope'." `
             "Verify -ClientId is correct and the proxy was deployed with the right EntraId:ClientId."
    }
    Write-Green "  [OK] /.well-known/openid-configuration -> scope '$expectedScope' present ($($t2.ElapsedMilliseconds)ms)"
    Mark-Pass "OAuth discovery doc" "scope present"
}
catch {
    $t2.Stop()
    Mark-Fail "OAuth discovery doc" "$_"
    Fail "Could not fetch OAuth discovery doc: $_"
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 -- Device Code flow against Entra
# ══════════════════════════════════════════════════════════════════════════════

Write-Step "2" "Device Code OAuth (Entra)"

$scope = "api://$ClientId/user_impersonation offline_access openid profile"
$deviceCodeEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"
$tokenEndpoint      = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

# Request device code
$t3 = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $dcBody = "client_id=$([Uri]::EscapeDataString($ClientId))&scope=$([Uri]::EscapeDataString($scope))"
    $dcResp  = Invoke-RestMethod -Uri $deviceCodeEndpoint -Method POST `
                   -ContentType "application/x-www-form-urlencoded" `
                   -Body $dcBody -ErrorAction Stop
    $t3.Stop()
}
catch {
    $t3.Stop()
    Mark-Fail "Entra device-code auth" "$_"
    $errBody = $_.ErrorDetails.Message
    if ($null -ne $errBody -and $errBody -match "AADSTS70011") {
        Fail "Device code request failed: invalid scope." `
             "Ensure the proxy app registration exposes scope 'user_impersonation' under api://$ClientId."
    }
    elseif ($null -ne $errBody -and $errBody -match "AADSTS700016") {
        Fail "Device code request failed: client not found." `
             "Check -TenantId and -ClientId are correct."
    }
    else {
        $hint = if ($null -ne $errBody) { "Raw error: $errBody" } else { "" }
        Fail "Device code request failed: $_" $hint
    }
}

$deviceCode      = $dcResp.device_code
$userCode        = $dcResp.user_code
$verificationUri = $dcResp.verification_uri
$verificationUriComplete = $dcResp.verification_uri_complete
$pollInterval    = [int](Coalesce $dcResp.interval 5)
$expiresIn       = [int](Coalesce $dcResp.expires_in 900)

# Display prominent action box
Write-Host ""
Write-Host "  +==============================================================+" -ForegroundColor Yellow
Write-Host "  |  ACTION REQUIRED -- sign in to authenticate                  |" -ForegroundColor Yellow
Write-Host "  |                                                              |" -ForegroundColor Yellow
Write-Host "  |  Open in your browser:                                       |" -ForegroundColor Yellow
Write-Host ("  |    {0,-52}|" -f $verificationUri) -ForegroundColor Yellow
Write-Host "  |                                                              |" -ForegroundColor Yellow
Write-Host "  |  Enter this code:                                            |" -ForegroundColor Yellow
Write-Host ("  |    {0,-52}|" -f $userCode) -ForegroundColor Cyan
Write-Host "  |                                                              |" -ForegroundColor Yellow
Write-Host ("  |  Waiting for sign-in (expires in {0} s)...              |" -f $expiresIn) -ForegroundColor Yellow
Write-Host "  +==============================================================+" -ForegroundColor Yellow
Write-Host ""

# Try to auto-open the browser
$urlToOpen = if ($null -ne $verificationUriComplete -and $verificationUriComplete -ne "") {
    $verificationUriComplete
} else {
    $verificationUri
}
try {
    if ($IsWindows) {
        Start-Process $urlToOpen
        Write-Yellow "  (Browser launched automatically with the code pre-filled)"
    }
    elseif ($IsMacOS) {
        & open $urlToOpen
        Write-Yellow "  (Browser launched automatically with the code pre-filled)"
    }
    elseif ($IsLinux) {
        & xdg-open $urlToOpen
        Write-Yellow "  (Browser launched automatically with the code pre-filled)"
    }
}
catch {
    Write-Yellow "  Could not launch browser automatically. Open the URL above manually."
}

# Poll for the token
$tAuthStart = [System.Diagnostics.Stopwatch]::StartNew()
$tokenResp  = $null

while ($true) {
    Start-Sleep -Seconds $pollInterval

    $elapsed = [Math]::Round($tAuthStart.ElapsedMilliseconds / 1000, 0)

    try {
        $tokenBody = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code" `
                   + "&device_code=$([Uri]::EscapeDataString($deviceCode))" `
                   + "&client_id=$([Uri]::EscapeDataString($ClientId))"

        $tokenResp = Invoke-RestMethod -Uri $tokenEndpoint -Method POST `
                         -ContentType "application/x-www-form-urlencoded" `
                         -Body $tokenBody -ErrorAction Stop
        break   # success
    }
    catch {
        $errJson = $null
        try { $errJson = ($_.ErrorDetails.Message | ConvertFrom-Json) } catch {}
        $errCode = if ($null -ne $errJson) { Get-Prop $errJson "error" "" } else { "" }

        if ($errCode -eq "authorization_pending") {
            Write-Host ("  ... waiting ({0}s elapsed)`r" -f $elapsed) -NoNewline
            continue
        }
        elseif ($errCode -eq "slow_down") {
            $pollInterval = $pollInterval * 2
            Write-Yellow "  Rate limited -- slowing poll to every ${pollInterval}s"
            continue
        }
        elseif ($errCode -eq "access_denied") {
            Mark-Fail "Entra device-code auth" "access_denied"
            Fail "User cancelled or denied the sign-in request."
        }
        elseif ($errCode -eq "expired_token") {
            Mark-Fail "Entra device-code auth" "expired_token"
            Fail "The device code expired before sign-in completed (ran for ${elapsed}s)." `
                 "Re-run the script and complete sign-in within ${expiresIn} seconds."
        }
        else {
            Mark-Fail "Entra device-code auth" "error=$errCode"
            $rawMsg = if ($null -ne $_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { "$_" }
            Fail "Token request failed (error=$errCode): $_" "Raw: $rawMsg"
        }
    }
}

$tAuthStart.Stop()

$accessToken = $tokenResp.access_token
if ($null -eq $accessToken -or $accessToken -eq "") {
    Mark-Fail "Entra device-code auth" "no access_token in response"
    Fail "Token response did not contain an access_token."
}

# Decode and display JWT claims
$claims = Decode-JwtPayload -Token $accessToken
$upn    = if ($null -ne $claims) {
    $v = Get-Prop $claims "upn" ""
    if ($v -eq "") { $v = Get-Prop $claims "preferred_username" "" }
    if ($v -eq "") { $v = Get-Prop $claims "email" "" }
    if ($v -eq "") { $v = "unknown" }
    $v
} else { "unknown" }

$expRaw = if ($null -ne $claims) { Get-Prop $claims "exp" "" } else { "" }
$expDt  = if ($expRaw -ne "") {
    try {
        [System.DateTimeOffset]::FromUnixTimeSeconds([long]$expRaw).ToString("yyyy-MM-dd HH:mm:ss UTC")
    } catch { $expRaw }
} else { "n/a" }

Write-Host ""
Write-Green "  [OK] Authentication successful ($($tAuthStart.ElapsedMilliseconds)ms total auth time)"
Write-Host "       User    : $upn"
Write-Host "       OID     : $(if ($null -ne $claims) { Get-Prop $claims 'oid' 'n/a' } else { 'n/a' })"
Write-Host "       TID     : $(if ($null -ne $claims) { Get-Prop $claims 'tid' 'n/a' } else { 'n/a' })"
Write-Host "       Audience: $(if ($null -ne $claims) { Get-Prop $claims 'aud' 'n/a' } else { 'n/a' })"
Write-Host "       Scope   : $(if ($null -ne $claims) { Get-Prop $claims 'scp' 'n/a' } else { 'n/a' })"
Write-Host "       Expires : $expDt"

Mark-Pass "Entra device-code auth" $upn

# ══════════════════════════════════════════════════════════════════════════════
# STEP 3 -- MCP initialize
# ══════════════════════════════════════════════════════════════════════════════

Write-Step "3" "MCP initialize"

$mcpUrl      = "$ProxyUrl/mcp"
$protocolVer = "2025-06-18"

$initBody = @{
    jsonrpc = "2.0"
    id      = 1
    method  = "initialize"
    params  = @{
        protocolVersion = $protocolVer
        capabilities    = @{}
        clientInfo      = @{
            name    = "test-mcp-script"
            version = "1.0.0"
        }
    }
} | ConvertTo-Json -Depth 10 -Compress

$mcpHeaders = @{
    "Authorization"        = "Bearer $accessToken"
    "Content-Type"         = "application/json"
    "Accept"               = "application/json, text/event-stream"
    "MCP-Protocol-Version" = $protocolVer
}

$t4 = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $initResponse = Invoke-WebRequest -Uri $mcpUrl -Method POST `
        -Headers $mcpHeaders `
        -Body $initBody -UseBasicParsing -ErrorAction Stop
    $t4.Stop()
}
catch {
    $t4.Stop()
    $status = Get-ExceptionStatus $_
    Mark-Fail "MCP initialize" "HTTP $status"
    if ($status -eq 401) {
        Fail "MCP /mcp returned 401 Unauthorized." `
             "Token rejected by proxy -- verify the access token audience ('aud' claim) is 'api://$ClientId' or '$ClientId'."
    }
    elseif ($status -eq 403) {
        Fail "MCP /mcp returned 403 Forbidden." `
             "The token is valid but the user lacks authorization. Check group membership and DownstreamAuthorizationFilter config."
    }
    else {
        Fail "MCP initialize request failed (HTTP $status): $_"
    }
}

# Capture optional Mcp-Session-Id (case-insensitive header lookup). The proxy
# runs stateless in ACA, so current deployments do not return or require this.
$SessionId = $null
foreach ($key in $initResponse.Headers.Keys) {
    if ($key -ieq "Mcp-Session-Id") {
        $hval = $initResponse.Headers[$key]
        if ($hval -is [System.Collections.Generic.List[string]]) {
            $SessionId = $hval[0]
        } else {
            $SessionId = [string]$hval
        }
        break
    }
}

$contentType = $initResponse.Headers["Content-Type"]
if ($contentType -is [System.Collections.Generic.List[string]]) { $contentType = $contentType[0] }
if ($null -eq $contentType) { $contentType = "" }

$initResult = Parse-McpResponse -Body $initResponse.Content -ContentType $contentType

if ($null -eq $initResult) {
    Mark-Fail "MCP initialize" "could not parse response"
    Fail "Could not parse the MCP initialize response (Content-Type: $contentType)."
}

$rpcErr = Get-Prop $initResult "error" ""
if ($rpcErr -ne "") {
    $errMsg = try { (Get-Prop $initResult.error "message" "$rpcErr") } catch { "$rpcErr" }
    Mark-Fail "MCP initialize" "JSON-RPC error: $errMsg"
    Fail "MCP initialize returned a JSON-RPC error: $errMsg"
}

$initResultInner = Get-Prop $initResult "result" $null
$serverProtoVer  = if ($null -ne $initResultInner) { Get-Prop $initResultInner "protocolVersion" "n/a" } else { "n/a" }
$serverInfoObj   = if ($null -ne $initResultInner) { Get-Prop $initResultInner "serverInfo" $null } else { $null }
$serverName      = if ($null -ne $serverInfoObj)   { Get-Prop $serverInfoObj "name" "n/a" }    else { "n/a" }
$serverVer       = if ($null -ne $serverInfoObj)   { Get-Prop $serverInfoObj "version" "n/a" } else { "n/a" }
$sessionLabel    = if ($null -ne $SessionId -and $SessionId -ne "") { "session=$SessionId" } else { "stateless" }

Write-Green "  [OK] MCP initialize -> $sessionLabel ($($t4.ElapsedMilliseconds)ms)"
Write-Host "       Protocol : $serverProtoVer"
Write-Host "       Server   : $serverName v$serverVer"

Mark-Pass "MCP initialize" "$sessionLabel, protocol=$serverProtoVer"

# Common headers for subsequent requests. Add the MCP session id only when a
# stateful deployment returned one during initialize.
$sessionHeaders = @{
    "Authorization"        = "Bearer $accessToken"
    "Content-Type"         = "application/json"
    "Accept"               = "application/json, text/event-stream"
    "MCP-Protocol-Version" = $protocolVer
}
if ($null -ne $SessionId -and $SessionId -ne "") {
    $sessionHeaders["Mcp-Session-Id"] = $SessionId
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 4 -- notifications/initialized
# ══════════════════════════════════════════════════════════════════════════════

Write-Step "4" "Send notifications/initialized"

$notifBody = '{"jsonrpc":"2.0","method":"notifications/initialized"}'

$t5 = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $notifResponse = Invoke-WebRequest -Uri $mcpUrl -Method POST `
        -Headers $sessionHeaders `
        -Body $notifBody -UseBasicParsing -ErrorAction Stop
    $t5.Stop()
    $notifStatus = $notifResponse.StatusCode
    if ($notifStatus -eq 202 -or $notifStatus -eq 200) {
        Write-Green "  [OK] notifications/initialized -> $notifStatus ($($t5.ElapsedMilliseconds)ms)"
    }
    else {
        Write-Yellow "  [WARN] notifications/initialized returned $notifStatus (expected 202) -- continuing"
    }
}
catch {
    $t5.Stop()
    $status = Get-ExceptionStatus $_
    Write-Yellow "  [WARN] notifications/initialized failed with HTTP $status -- continuing ($($t5.ElapsedMilliseconds)ms)"
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 5 -- tools/list
# ══════════════════════════════════════════════════════════════════════════════

Write-Step "5" "tools/list"

$listBody = '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

$t6 = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $listResponse = Invoke-WebRequest -Uri $mcpUrl -Method POST `
        -Headers $sessionHeaders `
        -Body $listBody -UseBasicParsing -ErrorAction Stop
    $t6.Stop()
}
catch {
    $t6.Stop()
    $status = Get-ExceptionStatus $_
    Mark-Fail "MCP tools/list" "HTTP $status"
    Fail "tools/list request failed (HTTP $status): $_"
}

$listCt = $listResponse.Headers["Content-Type"]
if ($listCt -is [System.Collections.Generic.List[string]]) { $listCt = $listCt[0] }
if ($null -eq $listCt) { $listCt = "" }

$listResult = Parse-McpResponse -Body $listResponse.Content -ContentType $listCt

if ($null -eq $listResult) {
    Mark-Fail "MCP tools/list" "could not parse response"
    Fail "Could not parse tools/list response."
}

$rpcErr = Get-Prop $listResult "error" ""
if ($rpcErr -ne "") {
    $errMsg = try { (Get-Prop $listResult.error "message" "$rpcErr") } catch { "$rpcErr" }
    Mark-Fail "MCP tools/list" "JSON-RPC error: $errMsg"
    Fail "tools/list returned a JSON-RPC error: $errMsg"
}

$listResultInner = Get-Prop $listResult "result" $null
$tools = if ($null -ne $listResultInner) {
    $t = $listResultInner.PSObject.Properties["tools"]
    if ($null -ne $t) { $t.Value } else { @() }
} else { @() }

if ($null -eq $tools) { $tools = @() }
$toolArray = @($tools)
$toolCount = $toolArray.Count

Write-Green "  [OK] tools/list -> $toolCount tool(s) ($($t6.ElapsedMilliseconds)ms)"

# Print tool table
$provenancePrefixPresent = $false
if ($toolCount -gt 0) {
    Write-Host ""
    Write-Host ("  {0,-45} {1}" -f "TOOL NAME", "DESCRIPTION (first 60 chars)")
    Write-Host ("  {0,-45} {1}" -f ("-" * 45), ("-" * 60))
    foreach ($tool in $toolArray) {
        $desc = Get-Prop $tool "description" ""
        if ($desc -match '^\[Source:') { $provenancePrefixPresent = $true }
        $shortDesc = if ($desc.Length -gt 60) { $desc.Substring(0, 57) + "..." } else { $desc }
        $tname = Get-Prop $tool "name" "(unnamed)"
        Write-Host ("  {0,-45} {1}" -f $tname, $shortDesc)
    }
    Write-Host ""
}

if ($provenancePrefixPresent) {
    Write-Green "  [OK] Provenance prefix '[Source: ...]' detected in tool descriptions (Phase 9 N5)"
    Mark-Pass "MCP tools/list" "$toolCount tools, provenance prefix present"
}
else {
    Write-Yellow "  [NOTE] Provenance prefix '[Source: ...]' not detected in tool descriptions."
    Write-Yellow "         This may be expected if the downstream descriptions don't include it."
    Mark-Pass "MCP tools/list" "$toolCount tools advertised"
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 6 -- tools/call
# ══════════════════════════════════════════════════════════════════════════════

Write-Step "6" "tools/call"

$selectedTool = $null

if ($ToolName -ne "") {
    # Use the explicitly specified tool
    $selectedTool = [PSCustomObject]@{ name = $ToolName }
    Write-Host "  Using specified tool: $ToolName"
}
elseif ($toolCount -eq 0) {
    Write-Yellow "  [SKIP] No tools available -- skipping tools/call"
    Mark-Pass "MCP tools/call" "skipped (no tools)"
}
else {
    # Interactive: prompt user to pick, default to first
    $isInteractive = $false
    try {
        $null = $Host.UI.RawUI.WindowSize
        $isInteractive = $true
    }
    catch {}

    if ($isInteractive) {
        Write-Host ""
        Write-Host "  Available tools:"
        $idx = 1
        foreach ($tool in $toolArray) {
            Write-Host ("  [{0}] {1}" -f $idx, (Get-Prop $tool "name" "?"))
            $idx++
        }
        Write-Host ""
        Write-Host -NoNewline "  Pick a tool [1-$toolCount] (default: 1): "
        $userInput = Read-Host
        if ($null -eq $userInput -or $userInput -eq "" -or $userInput -notmatch '^\d+$') {
            $userInput = "1"
        }
        $choice = [int]$userInput
        if ($choice -lt 1 -or $choice -gt $toolCount) { $choice = 1 }
        $selectedTool = $toolArray[$choice - 1]
    }
    else {
        # Non-interactive: use first tool
        $selectedTool = $toolArray[0]
        Write-Host "  Non-interactive mode -- using first tool: $(Get-Prop $selectedTool 'name' '?')"
    }
}

if ($null -ne $selectedTool) {
    $selectedToolName = Get-Prop $selectedTool "name" $ToolName

    # Parse the tool arguments
    $parsedArgs = $null
    try {
        $parsedArgs = $ToolArgs | ConvertFrom-Json
    }
    catch {
        Write-Yellow "  [WARN] Could not parse -ToolArgs as JSON -- using empty object"
        $parsedArgs = [PSCustomObject]@{}
    }

    # Build call body (ConvertTo-Json handles the nesting)
    $callBodyObj = @{
        jsonrpc = "2.0"
        id      = 3
        method  = "tools/call"
        params  = @{
            name      = $selectedToolName
            arguments = $parsedArgs
        }
    }
    $callBody = $callBodyObj | ConvertTo-Json -Depth 10 -Compress

    $t7 = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $callResponse = Invoke-WebRequest -Uri $mcpUrl -Method POST `
            -Headers $sessionHeaders `
            -Body $callBody -UseBasicParsing -ErrorAction Stop
        $t7.Stop()
    }
    catch {
        $t7.Stop()
        $status = Get-ExceptionStatus $_
        Mark-Fail "MCP tools/call" "HTTP $status"
        if ($status -eq 401) {
            Fail "tools/call returned 401 -- token may have expired during the test." `
                 "Re-run the script."
        }
        else {
            Fail "tools/call request failed (HTTP $status): $_"
        }
    }

    $callCt = $callResponse.Headers["Content-Type"]
    if ($callCt -is [System.Collections.Generic.List[string]]) { $callCt = $callCt[0] }
    if ($null -eq $callCt) { $callCt = "" }

    $callResult = Parse-McpResponse -Body $callResponse.Content -ContentType $callCt

    if ($null -eq $callResult) {
        Mark-Fail "MCP tools/call" "could not parse response"
        Fail "Could not parse tools/call response."
    }

    $rpcErr = Get-Prop $callResult "error" ""
    if ($rpcErr -ne "") {
        $errMsg = try { (Get-Prop $callResult.error "message" "$rpcErr") } catch { "$rpcErr" }
        Mark-Fail "MCP tools/call" "JSON-RPC error: $errMsg"
        Fail "tools/call returned a JSON-RPC error: $errMsg"
    }

    $callResultInner = Get-Prop $callResult "result" $null
    $content  = if ($null -ne $callResultInner) {
        $cp = $callResultInner.PSObject.Properties["content"]
        if ($null -ne $cp) { @($cp.Value) } else { @() }
    } else { @() }

    $isErrorProp = if ($null -ne $callResultInner) { Get-Prop $callResultInner "isError" $false } else { $false }
    $isError = $isErrorProp -eq $true

    Write-Green "  [OK] tools/call -> $selectedToolName ($($t7.ElapsedMilliseconds)ms)"

    $downstreamWrapping = $false
    if ($content.Count -gt 0) {
        Write-Host ""
        Write-Host "  Content blocks ($($content.Count)):"
        foreach ($block in $content) {
            $blockText = Get-Prop $block "text" ""
            if ($blockText -match '<downstream-content') {
                $downstreamWrapping = $true
            }
            $preview = if ($blockText.Length -gt 200) { $blockText.Substring(0, 197) + "..." } else { $blockText }
            $blockType = Get-Prop $block "type" "?"
            Write-Host "  -- type=$blockType --"
            Write-Host $preview
        }
        Write-Host ""
    }

    if ($isError) {
        Write-Yellow "  [NOTE] isError=true in response. If this mentions permissions, the user may lack"
        Write-Yellow "         access to that ADO resource -- this is not a proxy bug."
    }

    if ($downstreamWrapping) {
        Write-Green "  [OK] <downstream-content> marker present in result (Phase 10 N11 wrapping verified)"
        Mark-Pass "MCP tools/call" "$selectedToolName -> content received"
        Mark-Pass "Provenance wrapping" "<downstream-content> marker present"
    }
    else {
        Write-Yellow "  [NOTE] <downstream-content> marker not found. This may be expected if"
        Write-Yellow "         ProvenanceStyle is not 'Full' in the proxy configuration."
        Mark-Pass "MCP tools/call" "$selectedToolName -> content received (no wrapping tag)"
        Mark-Fail "Provenance wrapping" "<downstream-content> not found (check ProvenanceStyle config)"
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 7 -- DELETE session
# ══════════════════════════════════════════════════════════════════════════════

Write-Step "7" "DELETE session"

if ($null -eq $SessionId -or $SessionId -eq "") {
    Write-Yellow "  [SKIP] Stateless MCP transport -- no session to delete"
    Mark-Pass "DELETE session" "skipped (stateless transport)"
}
else {
    $t8 = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $deleteResponse = Invoke-WebRequest -Uri $mcpUrl -Method DELETE `
            -Headers @{
                "Authorization"  = "Bearer $accessToken"
                "Mcp-Session-Id" = $SessionId
            } -UseBasicParsing -ErrorAction Stop
        $t8.Stop()
        $delStatus = $deleteResponse.StatusCode
        if ($delStatus -eq 200 -or $delStatus -eq 204) {
            Write-Green "  [OK] DELETE session -> $delStatus ($($t8.ElapsedMilliseconds)ms)"
        }
        else {
            Write-Yellow "  [NOTE] DELETE session returned $delStatus ($($t8.ElapsedMilliseconds)ms)"
        }
    }
    catch {
        $t8.Stop()
        $status = Get-ExceptionStatus $_
        if ($status -eq 405) {
            Write-Yellow "  [OK/NOTE] DELETE returned 405 (server does not allow client-initiated session termination -- expected)"
        }
        else {
            Write-Yellow "  [WARN] DELETE session returned $status -- continuing ($($t8.ElapsedMilliseconds)ms)"
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 8 -- Summary table
# ══════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " RESULT" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

$allPassed = $true
foreach ($key in $SummaryKeys) {
    $pass   = $SummaryPass[$key]
    $detail = $SummaryDetail[$key]
    if ($pass) {
        $icon  = "[PASS]"
        $color = "Green"
    }
    else {
        $icon      = "[FAIL]"
        $color     = "Red"
        $allPassed = $false
    }
    $label = $key.PadRight(30)
    Write-Host (" {0} {1} {2}" -f $icon, $label, $detail) -ForegroundColor $color
}

Write-Host "================================================================" -ForegroundColor Cyan

if ($allPassed) {
    Write-Host " ALL CHECKS PASSED -- the proxy is end-to-end functional." -ForegroundColor Green
    Write-Host " Total elapsed: $(Elapsed)" -ForegroundColor Green
}
else {
    Write-Host " SOME CHECKS FAILED -- see details above." -ForegroundColor Red
    Write-Host " Total elapsed: $(Elapsed)" -ForegroundColor Red
}

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

if (-not $allPassed) { exit 1 }
