Function CreateUser{

    <#
        .SYNOPSIS
            Creates a user in an active directory environment based on random data
        
        .DESCRIPTION
            Starting with the root container this tool randomly places users in the domain.
        
        .PARAMETER Domain
            The stored value of get-addomain is used for this.  It is used to call the PDC and other items in the domain
        
        .PARAMETER OUList
            The stored value of get-adorganizationalunit -filter *.  This is used to place users in random locations.
        
        .PARAMETER ScriptDir
            The location of the script.  Pulling this into a parameter to attempt to speed up processing.
        
        .EXAMPLE
            
     
        
        .NOTES
            
            
            Unless required by applicable law or agreed to in writing, software
            distributed under the License is distributed on an "AS IS" BASIS,
            WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
            See the License for the specific language governing permissions and
            limitations under the License.
            
            Author's blog: https://www.secframe.com
    
        
    #>
    [CmdletBinding()]
    
    param
    (
        [Parameter(Mandatory = $false,
            Position = 1,
            HelpMessage = 'Supply a result from get-addomain')]
            [Object[]]$Domain,
        [Parameter(Mandatory = $false,
            Position = 2,
            HelpMessage = 'Supply a result from get-adorganizationalunit -filter *')]
            [Object[]]$OUList,
        [Parameter(Mandatory = $false,
            Position = 3,
            HelpMessage = 'Supply the script directory for where this script is stored')]
        [string]$ScriptDir
    )
    
        if(!$PSBoundParameters.ContainsKey('Domain')){
                $setDC = (Get-ADDomain).pdcemulator
                $dnsroot = (get-addomain).dnsroot
            }
            else {
                $setDC = $Domain.pdcemulator
                $dnsroot = $Domain.dnsroot
            }
        if (!$PSBoundParameters.ContainsKey('OUList')){
            $OUsAll = get-adobject -Filter {objectclass -eq 'organizationalunit'} -ResultSetSize 300
        }else {
            $OUsAll = $OUList
        }
        if (!$PSBoundParameters.ContainsKey('ScriptDir')){
            function Get-ScriptDirectory {
                Split-Path -Parent $PSCommandPath
            }
            $scriptPath = Get-ScriptDirectory
        }else{
            $scriptpath = $scriptdir
        }
    

        

    
    function New-SWRandomPassword {
        <#
        .Synopsis
           Generates one or more complex passwords designed to fulfill the requirements for Active Directory
        .DESCRIPTION
           Generates one or more complex passwords designed to fulfill the requirements for Active Directory
        .EXAMPLE
           New-SWRandomPassword
           C&3SX6Kn
    
           Will generate one password with a length between 8  and 12 chars.
        .EXAMPLE
           New-SWRandomPassword -MinPasswordLength 8 -MaxPasswordLength 12 -Count 4
           7d&5cnaB
           !Bh776T"Fw
           9"C"RxKcY
           %mtM7#9LQ9h
    
           Will generate four passwords, each with a length of between 8 and 12 chars.
        .EXAMPLE
           New-SWRandomPassword -InputStrings abc, ABC, 123 -PasswordLength 4
           3ABa
    
           Generates a password with a length of 4 containing atleast one char from each InputString
        .EXAMPLE
           New-SWRandomPassword -InputStrings abc, ABC, 123 -PasswordLength 4 -FirstChar abcdefghijkmnpqrstuvwxyzABCEFGHJKLMNPQRSTUVWXYZ
           3ABa
    
           Generates a password with a length of 4 containing atleast one char from each InputString that will start with a letter from 
           the string specified with the parameter FirstChar
        .OUTPUTS
           [String]
        .NOTES
           Written by Simon WÃ¥hlin, blog.simonw.se
           I take no responsibility for any issues caused by this script.
        .FUNCTIONALITY
           Generates random passwords
        .LINK
           http://blog.simonw.se/powershell-generating-random-password-for-active-directory/
       
        #>
        [CmdletBinding(DefaultParameterSetName='FixedLength',ConfirmImpact='None')]
        [OutputType([String])]
        Param
        (
            # Specifies minimum password length
            [Parameter(Mandatory=$false,
                       ParameterSetName='RandomLength')]
            [ValidateScript({$_ -gt 0})]
            [Alias('Min')] 
            [int]$MinPasswordLength = 12,
            
            # Specifies maximum password length
            [Parameter(Mandatory=$false,
                       ParameterSetName='RandomLength')]
            [ValidateScript({
                    if($_ -ge $MinPasswordLength){$true}
                    else{Throw 'Max value cannot be lesser than min value.'}})]
            [Alias('Max')]
            [int]$MaxPasswordLength = 20,
    
            # Specifies a fixed password length
            [Parameter(Mandatory=$false,
                       ParameterSetName='FixedLength')]
            [ValidateRange(1,2147483647)]
            [int]$PasswordLength = 8,
            
            # Specifies an array of strings containing charactergroups from which the password will be generated.
            # At least one char from each group (string) will be used.
            [String[]]$InputStrings = @('abcdefghijkmnpqrstuvwxyz', 'ABCEFGHJKLMNPQRSTUVWXYZ', '23456789', '!#%&'),
    
            # Specifies a string containing a character group from which the first character in the password will be generated.
            # Useful for systems which requires first char in password to be alphabetic.
            [String] $FirstChar,
            
            # Specifies number of passwords to generate.
            [ValidateRange(1,2147483647)]
            [int]$Count = 1
        )
        Begin {
            Function Get-Seed{
                # Generate a seed for randomization
                $RandomBytes = New-Object -TypeName 'System.Byte[]' 4
                $Random = New-Object -TypeName 'System.Security.Cryptography.RNGCryptoServiceProvider'
                $Random.GetBytes($RandomBytes)
                [BitConverter]::ToUInt32($RandomBytes, 0)
            }
        }
        Process {
            For($iteration = 1;$iteration -le $Count; $iteration++){
                $Password = @{}
                # Create char arrays containing groups of possible chars
                [char[][]]$CharGroups = $InputStrings
    
                # Create char array containing all chars
                $AllChars = $CharGroups | ForEach-Object {[Char[]]$_}
    
                # Set password length
                if($PSCmdlet.ParameterSetName -eq 'RandomLength')
                {
                    if($MinPasswordLength -eq $MaxPasswordLength) {
                        # If password length is set, use set length
                        $PasswordLength = $MinPasswordLength
                    }
                    else {
                        # Otherwise randomize password length
                        $PasswordLength = ((Get-Seed) % ($MaxPasswordLength + 1 - $MinPasswordLength)) + $MinPasswordLength
                    }
                }
    
                # If FirstChar is defined, randomize first char in password from that string.
                if($PSBoundParameters.ContainsKey('FirstChar')){
                    $Password.Add(0,$FirstChar[((Get-Seed) % $FirstChar.Length)])
                }
                # Randomize one char from each group
                Foreach($Group in $CharGroups) {
                    if($Password.Count -lt $PasswordLength) {
                        $Index = Get-Seed
                        While ($Password.ContainsKey($Index)){
                            $Index = Get-Seed                        
                        }
                        $Password.Add($Index,$Group[((Get-Seed) % $Group.Count)])
                    }
                }
    
                # Fill out with chars from $AllChars
                for($i=$Password.Count;$i -lt $PasswordLength;$i++) {
                    $Index = Get-Seed
                    While ($Password.ContainsKey($Index)){
                        $Index = Get-Seed                        
                    }
                    $Password.Add($Index,$AllChars[((Get-Seed) % $AllChars.Count)])
                }
                Write-Output -InputObject $(-join ($Password.GetEnumerator() | Sort-Object -Property Name | Select-Object -ExpandProperty Value))
            }
        }
    }
    
        
    #get owner all parameters and store as variable to call upon later
           
        
    
    #=======================================================================
    
    #will work on adding things to containers later $ousall += get-adobject -Filter {objectclass -eq 'container'} -ResultSetSize 300|where-object -Property objectclass -eq 'container'|where-object -Property distinguishedname -notlike "*}*"|where-object -Property distinguishedname -notlike  "*DomainUpdates*"
    
    $ouLocation = (Get-Random $OUsAll).distinguishedname
    
    
    
    $accountType = 1..100|get-random 
    if($accountType -le 10){ # X percent chance of being a service account
    #service
    $nameSuffix = "SA"
    $description = 'Created with secframe.com/badblood.'
    #removing do while loop and making random number range longer, sorry if the account is there already
    # this is so that I can attempt to import multithreading on user creation
    
        $name = ""+ (Get-Random -Minimum 100 -Maximum 9999999999) + "$nameSuffix"
        
        
    }else{
        $surname = get-content('.\AD_Users_Create\Names\familynames-usa-top1000.txt')|get-random
    $genderpreference = 0,1|get-random
    if ($genderpreference -eq 0){$givenname = get-content('.\AD_Users_Create\Names\femalenames-usa-top1000.txt')|get-random}else{$givenname = get-content('.\AD_Users_Create\Names\malenames-usa-top1000.txt')|get-random}
    $name = $givenname+"_"+$surname
    }
    
        $departmentnumber = [convert]::ToInt32('9999999') 
        
        
    #Need to figure out how to do the L attribute
    $description = ''
    #$pwd = New-SWRandomPassword -MinPasswordLength 22 -MaxPasswordLength 25
    #======================================================================
    # 
    write-host "Create password and description" 
    $passwordinDesc = Get-Random -Maximum 100
    $passwordInWordlist = Get-Random -Maximum 100

    if ($passInWordList -lt 50) {
        $pwd = Get-Random -InputObject (get-content ('.\AD_Users_Create\wordlist.txt'))
        }
    else {
        $pwd = New-SWRandomPassword -MinPasswordLength 12 -MaxPasswordLength 25 
        }
    
    if ($passwordinDesc -lt 8) { 
        $description = 'Just so I dont forget my password is ' + $pwd 
    }
    write-host "Create user" 
    new-aduser -server $setdc  -Description $Description -DisplayName $name -name $name -SamAccountName $name -Surname $name -Enabled $true -Path $ouLocation -AccountPassword (ConvertTo-SecureString ($pwd) -AsPlainText -force)

    #===============================
    #SET ATTRIBUTES - no additional attributes set at this time besides UPN
    #Todo: Set SPN for kerberoasting.  Example attribute edit is in createcomputers.ps1
    #===============================
    write-host "Set UP" 
    $upn = $name + '@' + $dnsroot
    try{Set-ADUser -Identity $name -UserPrincipalName "$upn" }
    catch{}

    #================================================
    #SET SOME RANDOM AD AccountControl Randomness
    #================================================
    write-host "Set Password Not Required" 
    $adacPaswordNotRequired = Get-Random -Maximum 100
        if ($adacPaswordNotRequired -lt 5) {
        Set-ADAccountControl $name -PasswordNotRequired $true
    }
    write-host "Set Password Never Expires" 
    $adacPasswordNeverExpires = Get-Random -Maximum 100
    if ($adacPasswordNeverExpires -lt 5) {
        Set-ADAccountControl $name -PasswordNeverExpires $true
    }
    write-host "Set Cannot Change Password" 
    $adacCannotChangePassword = Get-Random -Maximum 100
    if ($adacCannotChangePassword -lt 5) {
        Set-ADAccountControl $name -CannotChangePassword $true
    }

    write-host "Set No Delegation" 
    $adacNoDelegation = Get-Random -Maximum 100
    if ($adacNoDelegation -lt 5){
        Set-ADAccountControl $name -AccountNotDelegated $true
    }

    write-host "Set TrustedDelegation" 
    $adacTrustedToAuthDelegation = Get-Random -Maximum 100
    if ($adacTrustedToAuthDelegation -lt 4){
        Set-ADAccountControl $name -TrustedToAuthForDelegation $true
    }
    write-host "Set Change Pass at Logon" 
    $adacChangePassAtLogon = Get-Random -Maximum 100
    if ($adacChangePassAtLogon -lt 4){
        Set-ADUser -Identity $name -ChangePasswordAtLogon $true
    }

    ### Set reveriseble encryption on, store a pasword in attribute.
    write-host "Set Reversible Encryption" 
    $adacReversibleEncryption = Get-Random -Maximum 100
    if ($adacReversibleEncryption -lt 8){

        Set-ADAccountControl $name -AllowReversiblePasswordEncryption $true
        $newpass = New-SWRandomPassword -MinPasswordLength 22 -MaxPasswordLength 25
        Set-ADAccountPassword -Identity $name -NewPassword (ConvertTo-SecureString -AsPlainText $newpass -Force)
        write-host "UnSet Reversible Encryption" 
        $adacReversibleEncryptionUnset = Get-Random -Maximum 100
        # This will update the ADAccountcontrol but retain the stored reversible encrypted password in the AD Database.  Discoverable by NTDS.dit enumeration, ect.
        if ($adacReversibleEncryptionUnset -lt 50){
            Set-ADAccountControl $name -AllowReversiblePasswordEncryption $false
            }
        }
    

    ## Disable random accounts
    write-host "Set Disabled Account" 
    $adacDisabled = Get-Random -Maximum 100
    if ($adacDisabled -lt 5) {
        Set-ADAccountControl $name -Enabled $false
    }

    #Set Random Department
    write-host "Set Department" 
    $aduserDepartment = Get-Random -InputObject (get-content '.\AD_Users_Create\Names\departments.txt')
     try{
         Set-ADUser -Identity $name -Department "$aduserDepartment" 
     }
    catch{
    }

    #Set Random Job Title

    #write-host "Set Title" 
    #$aduserTitle = Get-Random -InputObject (get-content '.\AD_Users_Create\Names\titles.txt')
    # try{
    #     Set-ADUser -Identity $name -Title "$aduserTitle" 
    # }
    #catch{
    #}

    #Set Random Employee
    write-host "Set Employee Number" 
    $aduserEmpNum = Get-Random -Maximum 10000
     try{
         Set-ADUser -Identity $name -EmployeeNumber $aduserEmpNum
     }
    catch{
    }

    #Set Random POBox
    write-host "SET PoBox" 
    $aduserPOB = Get-Random -Maximum 10000
     try{
         Set-ADUser -Identity $name -POBox $aduserPOB
     }
    catch{
    }

    #Set Random PostalCode
    write-host "SET PostalCode" 
    $aduserPostalCode = Get-Random -Maximum 10000
     try{
         Set-ADUser -Identity $name -PostalCode $aduserPostalCode
     }
    catch{
    }
    #Set Street Address to badblood tag
    write-host "Set Street" 
    Set-ADUser -Identity $name -Street "Created with secframe.com/badblood."


        
    $pwd = ''
    
    
    ################################
    #End Create User Objects
    ################################
    
    }