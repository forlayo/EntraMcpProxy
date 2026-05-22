#!/usr/bin/env pwsh
#Requires -Version 7

<#
.SYNOPSIS
    Deploy EntraMcpProxy to Azure Container Apps using Bicep.

.DESCRIPTION
    Validates prerequisites, runs a what-if diff, prompts for confirmation,
    then deploys iac/main.bicep using iac/parameters.bicepparam.

.PARAMETER ResourceGroup
    Azure resource group to deploy into. Will be prompted if not supplied.

.PARAMETER ParametersFile
    Path to the .bicepparam file. Defaults to iac/parameters.bicepparam
    in the same directory as this script.

.PARAMETER DeploymentName
    Name for the deployment record in Azure. Defaults to 'entra-mcp-proxy-<timestamp>'.

.EXAMPLE
    pwsh iac/deploy.ps1 -ResourceGroup rg-entra-mcp-prod
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $ResourceGroup,

    [string] $ParametersFile = '',

    [string] $DeploymentName = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Write-Step([string] $msg) {
    Write-Host "`n>> $msg" -ForegroundColor Cyan
}

function Write-Success([string] $msg) {
    Write-Host "   $msg" -ForegroundColor Green
}

function Write-Warn([string] $msg) {
    Write-Host "   WARNING: $msg" -ForegroundColor Yellow
}

function Write-Fail([string] $msg) {
    Write-Host "   ERROR: $msg" -ForegroundColor Red
}

# ---------------------------------------------------------------------------
# Resolve paths
# ---------------------------------------------------------------------------

$scriptDir = $PSScriptRoot
if (-not $scriptDir) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}

$bicepFile = Join-Path $scriptDir 'main.bicep'

if (-not $ParametersFile) {
    $ParametersFile = Join-Path $scriptDir 'parameters.bicepparam'
}

if (-not $DeploymentName) {
    $DeploymentName = "entra-mcp-proxy-$(Get-Date -Format 'yyyyMMddHHmmss')"
}

# ---------------------------------------------------------------------------
# Step 1 — Check prerequisites
# ---------------------------------------------------------------------------

Write-Step 'Checking prerequisites...'

# az CLI
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Fail 'Azure CLI (az) is not installed or not on PATH.'
    Write-Host '   Install from: https://learn.microsoft.com/cli/azure/install-azure-cli' -ForegroundColor Yellow
    exit 1
}
Write-Success "az CLI found: $(az version --query '\"azure-cli\"' -o tsv 2>$null)"

# az login check
$account = az account show 2>$null | ConvertFrom-Json
if (-not $account) {
    Write-Fail 'Not logged in to Azure. Run: az login'
    exit 1
}
Write-Success "Logged in as: $($account.user.name)"
Write-Success "Subscription : $($account.name) ($($account.id))"
Write-Host ''

# bicep — prefer az bicep, fall back to standalone bicep binary
$useBicepCli = $false
try {
    $null = az bicep version 2>$null
    Write-Success 'Bicep available via az bicep'
} catch {
    if (Get-Command bicep -ErrorAction SilentlyContinue) {
        $useBicepCli = $true
        Write-Success "Standalone bicep found: $(bicep --version)"
    } else {
        Write-Warn 'bicep CLI not found — attempting to install via az bicep install...'
        az bicep install
    }
}

# Parameters file
if (-not (Test-Path $ParametersFile)) {
    Write-Fail "Parameters file not found: $ParametersFile"
    Write-Host '   Copy iac/parameters.example.bicepparam to iac/parameters.bicepparam and fill in your values.' -ForegroundColor Yellow
    exit 1
}
Write-Success "Parameters file: $ParametersFile"

# Bicep template
if (-not (Test-Path $bicepFile)) {
    Write-Fail "Bicep template not found: $bicepFile"
    exit 1
}
Write-Success "Bicep template: $bicepFile"

# ---------------------------------------------------------------------------
# Step 2 — Validate the resource group exists
# ---------------------------------------------------------------------------

Write-Step "Validating resource group '$ResourceGroup'..."

$rg = az group show --name $ResourceGroup 2>$null | ConvertFrom-Json
if (-not $rg) {
    Write-Fail "Resource group '$ResourceGroup' not found in current subscription."
    Write-Host "   Create it with: az group create --name $ResourceGroup --location <location>" -ForegroundColor Yellow
    exit 1
}
Write-Success "Resource group exists: $($rg.location)"

# ---------------------------------------------------------------------------
# Step 3 — What-if diff
# ---------------------------------------------------------------------------

Write-Step 'Running what-if diff (no changes will be made)...'
Write-Host ''

$whatIfArgs = @(
    'deployment', 'group', 'what-if'
    '--resource-group', $ResourceGroup
    '--name', $DeploymentName
    '--template-file', $bicepFile
    '--parameters', $ParametersFile
    '--result-format', 'FullResourcePayloads'
)

az @whatIfArgs
$whatIfExit = $LASTEXITCODE

if ($whatIfExit -ne 0) {
    Write-Host ''
    Write-Fail 'What-if failed. Fix the errors above before deploying.'
    exit 1
}

# ---------------------------------------------------------------------------
# Step 4 — Confirmation prompt
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '================================================================' -ForegroundColor Yellow
Write-Host '  Review the changes above carefully before proceeding.' -ForegroundColor Yellow
Write-Host '================================================================' -ForegroundColor Yellow
Write-Host ''
$answer = Read-Host 'Proceed with deployment? [y/N]'

if ($answer -notmatch '^[Yy]$') {
    Write-Host 'Deployment cancelled.' -ForegroundColor Yellow
    exit 0
}

# ---------------------------------------------------------------------------
# Step 5 — Deploy
# ---------------------------------------------------------------------------

Write-Step "Deploying '$DeploymentName' to resource group '$ResourceGroup'..."
Write-Host ''

$deployArgs = @(
    'deployment', 'group', 'create'
    '--resource-group', $ResourceGroup
    '--name', $DeploymentName
    '--template-file', $bicepFile
    '--parameters', $ParametersFile
    '--output', 'json'
)

$deployOutput = az @deployArgs
$deployExit = $LASTEXITCODE

if ($deployExit -ne 0) {
    Write-Host ''
    Write-Fail 'Deployment failed. Check the output above for details.'
    exit 1
}

# ---------------------------------------------------------------------------
# Step 6 — Print outputs
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '================================================================' -ForegroundColor Green
Write-Host '  DEPLOYMENT SUCCEEDED' -ForegroundColor Green
Write-Host '================================================================' -ForegroundColor Green
Write-Host ''

try {
    $result = $deployOutput | ConvertFrom-Json
    $outputs = $result.properties.outputs

    $fqdn        = $outputs.appFqdn.value
    $mcpUrl      = $outputs.mcpEndpointUrl.value
    $healthzUrl  = $outputs.healthzUrl.value
    $discoveryUrl = $outputs.oauthDiscoveryUrl.value
    $nextSteps   = $outputs.nextStepsMessage.value

    Write-Host "  App FQDN       : $fqdn" -ForegroundColor White
    Write-Host "  MCP Endpoint   : $mcpUrl" -ForegroundColor White
    Write-Host "  Health Check   : $healthzUrl" -ForegroundColor White
    Write-Host "  OAuth Discovery: $discoveryUrl" -ForegroundColor White
    Write-Host ''
    Write-Host $nextSteps -ForegroundColor Cyan
} catch {
    Write-Warn 'Could not parse deployment outputs — deployment succeeded but output display failed.'
    Write-Host $deployOutput
}
