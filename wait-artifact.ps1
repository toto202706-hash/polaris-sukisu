#Requires -Version 7
<#
  wait-artifact.ps1 - 等待正在运行的 Actions 构建并下载 boot 镜像
#>
param([string]$WorkDir = 'D:\新建文件夹\刷机\ghbuild')
$ErrorActionPreference='Stop'
Set-Location $WorkDir
$run = gh run list --workflow build.yml --limit 1 --json databaseId,status,conclusion | ConvertFrom-Json
$id = $run[0].databaseId
Write-Host "run id: $id"
while($true){
  $j = gh run view $id --json status,conclusion | ConvertFrom-Json
  Write-Host ("[{0}] {1}/{2}" -f (Get-Date -Format HH:mm:ss), $j.status, $j.conclusion)
  if($j.status -eq 'completed'){ break }
  Start-Sleep -Seconds 30
}
if($j.conclusion -ne 'success'){ Write-Host "构建失败，取日志:"; gh run view $id --log-failed | Select-Object -Last 80; exit 1 }
Remove-Item -Recurse -Force .\artifact -ErrorAction SilentlyContinue
gh run download $id -n boot-artifact -D .\artifact
Get-ChildItem .\artifact
