#
#GET ALL AFFILIATE CODES FROM ALL OUS in production
function Get-ScriptDirectory {
    Split-Path -Parent $PSCommandPath
}
$scriptPath = Get-ScriptDirectory

$TopLevelOUs = @('Admin', 'Tier 1','Tier 2','Stage', 'Quarantine', 'Grouper-Groups', 'People','Testing','.SecFrame.com')
    
$AdminSubOUs = @('Tier 0', 'Tier 1', 'Tier 2', 'Staging') 
    #loop before the ou name by making T#-OBJECT name as the OU
$AdminobjectOUs = @('Accounts', 'Servers', 'Devices', 'Permissions','Roles') 
#########################
$skipSubOUs = @('Deprovision', 'Quarantine', 'Groups')
#########################
#$tierOUs = @('Tier 1', 'Tier 2')
$ObjectSubOUs = @('ServiceAccounts', 'Groups', 'Devices','Test')


#Consodated list of all 3 letter codes which IAM uses. 
$3LetterCodeCSV = $scriptPath + '\3lettercodes.csv'


Set-Location c:
$dn = (Get-ADDomain).distinguishedname
#=============================================
#ROUND:1
#Create Top Level OUS
#=============================================
Write-host "Creating Tiered OU Structure" -ForegroundColor Green
$topOUCount = $TopLevelOUs.count
$x = 1
foreach ($name in $TopLevelOUs) {
    Write-Progress -Activity "Deploying OU Structure" -Status "Top Level OU Status:" -PercentComplete ($x/$topOUCount*100)
    #New-ADOrganizationalUnit -Name $Name -ProtectedFromAccidentalDeletion:$true
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$Name'")) { New-ADOrganizationalUnit -Name $Name -ProtectedFromAccidentalDeletion $true } else { Write-Host "OU '$Name' already exists." }
    $fulldn = "OU=" + $name + "," + $dn 
    #$toplevelouinfo = Get-ADOrganizationalUnit $fulldn
    #=====================================================================================
    #ROUND:2
    #Create First level Down Sub OUs in Privileged Access, and Provisioned Users
    #=====================================================================================
    if ($name -eq $TopLevelOUs[0]) {

        foreach ($adminsubou in $AdminSubOUs) {
            if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$adminsubou' -and DistinguishedName -like '*$fulldn*'")) { New-ADOrganizationalUnit -Name $adminsubou -Path $fulldn } else { Write-Host "OU '$adminsubou' under '$fulldn' already exists." }
            #New-ADOrganizationalUnit -Name $adminsubou -Path $fulldn
            $adminsubfulldn = "OU=" + $adminsubou + "," + $fulldn
                    
            if ($adminsubou -eq "Staging") {                          
            }     
                                 
            else {
                foreach ($AdminobjectOU in $AdminobjectOUs) {
                    #add name together
                    if ($adminsubou -eq 'Tier 0'){$adminOUPrefix = "T0-"}
                    elseif ($adminsubou -eq 'Tier 1'){$adminOUPrefix = "T1-"}
                    elseif ($adminsubou -eq 'Tier 2'){$adminOUPrefix = "T2-"}
                    $adminobjectoucombo = $adminOUPrefix + $adminobjectou

                    #New-ADOrganizationalUnit -Name $adminobjectoucombo -Path $adminsubfulldn
                    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$adminobjectoucombo' -and DistinguishedName -like '*$adminsubfulldn*'")) { New-ADOrganizationalUnit -Name $adminobjectoucombo -Path $adminsubfulldn } else { Write-Host "OU '$adminobjectoucombo' under '$adminsubfulldn' already exists." }
                }
            }
        }
    }
    elseif ($skipSubOUs -contains $name) {
        #this skips the creation of the sub containers
    }
    elseif (($name -eq 'Tier 1') -or ($name -eq 'Tier 2') -or ($name -eq 'Stage')) {
        $fulldn = "OU=" + $name + "," + $dn 
        $csvlist = @()
        $csvlist = import-csv $3LetterCodeCSV

        foreach ($ou in $csvlist) {
            #New-ADOrganizationalUnit -Name ($ou.name) -Path $fulldn -Description ($ou.description)
            if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$($ou.name)' -and DistinguishedName -like '*$fulldn*'")) { New-ADOrganizationalUnit -Name $ou.name -Path $fulldn -Description $ou.description } else { Write-Host "OU '$($ou.name)' under '$fulldn' already exists." }
            $csvdn = "OU=" + $ou.name + "," + $fulldn 
            
            foreach ($ObjectSubOU in $ObjectSubOUs) {
                #New-ADOrganizationalUnit -Name $ObjectSubOU -Path $csvdn
                if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$ObjectSubOU' -and DistinguishedName -like '*$csvdn*'")) { New-ADOrganizationalUnit -Name $ObjectSubOU -Path $csvdn } else { Write-Host "OU '$ObjectSubOU' under '$csvdn' already exists." }
                $Objectfulldn = "OU=" + $ObjectSubOU + "," + $csvdn
            }
        }
    }

    elseif (($name -eq 'People')) {
        $fulldn = "OU=" + $name + "," + $dn 
        $csvlist = @()
        $csvlist = import-csv $3LetterCodeCSV
        


        foreach ($ou in $csvlist) {
            #New-ADOrganizationalUnit -Name ($ou.name) -Path $fulldn -Description ($ou.description)
            if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$($ou.name)' -and DistinguishedName -like '*$fulldn*'")) { New-ADOrganizationalUnit -Name $ou.name -Path $fulldn -Description $ou.description } else { Write-Host "OU '$($ou.name)' under '$fulldn' already exists." }
            $csvdn = "OU=" + $ou.name + "," + $fulldn 
            
        }
        #Create Two Sub OUs in People OU required for IDM provisioning 

        #New-ADOrganizationalUnit -Name 'Deprovisioned' -Path $fulldn -Description 'User account that have been deprovisioned by the IDM System'
        if (-not (Get-ADOrganizationalUnit -Filter "Name -eq 'Deprovisioned' -and DistinguishedName -like '*$fulldn*'")) { New-ADOrganizationalUnit -Name 'Deprovisioned' -Path $fulldn -Description 'User accounts that have been deprovisioned by the IDM System' } else { Write-Host "OU 'Deprovisioned' under '$fulldn' already exists." }

        #New-ADOrganizationalUnit -Name 'Unassociated' -Path $fulldn -Description 'User Object that do have have any department affliation'
        if (-not (Get-ADOrganizationalUnit -Filter "Name -eq 'Unassociated' -and DistinguishedName -like '*$fulldn*'")) { New-ADOrganizationalUnit -Name 'Unassociated' -Path $fulldn -Description 'User objects that do not have any department affiliation' } else { Write-Host "OU 'Unassociated' under '$fulldn' already exists." }

    }
    
    else {}
    $x++
}
    





