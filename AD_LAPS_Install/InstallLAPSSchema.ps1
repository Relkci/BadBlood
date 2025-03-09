function Get-ScriptDirectory {
    Split-Path -Parent $PSCommandPath
}
$scriptPath = Get-ScriptDirectory

# copy-item -path ($scriptpath + "\admpwd.ps") -destination "C:\Windows\System32\WindowsPowerShell\v1.0\Modules"
if (-not (Test-Path "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\admpwd.ps")) { Copy-Item -Path ($scriptpath + "\admpwd.ps") -Destination "C:\Windows\System32\WindowsPowerShell\v1.0\Modules" } else { Write-Host "File 'admpwd.ps' already exists in the destination." }

get-childitem -path ($scriptpath + "\admpwd.ps") -recurse |Foreach-object {
    #Copy-item -literalpath $_.fullname -destination "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\admpwd.ps"
    if (-not (Test-Path "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\admpwd.ps")) { Copy-Item -LiteralPath $_.FullName -Destination "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\admpwd.ps" } else { Write-Host "File 'admpwd.ps' already exists in the destination." }

}
# copy-item -path ($scriptpath + "\AdmPwd.admx") -destination "C:\Windows\PolicyDefinitions"
if (-not (Test-Path "C:\Windows\PolicyDefinitions\AdmPwd.admx")) { Copy-Item -Path ($scriptpath + "\AdmPwd.admx") -Destination "C:\Windows\PolicyDefinitions" } else { Write-Host "File 'AdmPwd.admx' already exists in the destination." }

#copy-item -path ($scriptpath + "\AdmPwd.adml") -destination "C:\Windows\PolicyDefinitions\en-US"
if (-not (Test-Path "C:\Windows\PolicyDefinitions\en-US\AdmPwd.adml")) { Copy-Item -Path ($scriptpath + "\AdmPwd.adml") -Destination "C:\Windows\PolicyDefinitions\en-US" } else { Write-Host "File 'AdmPwd.adml' already exists in the destination." }

Import-Module ADMPwd.ps
Update-AdmPwdADSchema
Set-AdmPwdComputerSelfPermission -OrgUnit (Get-ADDomain).distinguishedname