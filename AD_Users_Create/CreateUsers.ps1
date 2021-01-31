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
    
    
    if((Get-Random -Maximum 100) -le 10){
        $name = ""+ (Get-Random -Minimum 100 -Maximum 999999999) + "SA"
        $surname = "SA" 
        $givenname = $name 
    }
    else
    {
        $surname = get-content('.\AD_Users_Create\Names\familynames-usa-top1000.txt')|get-random
        $genderpreference = 0,1|get-random
        $givenname = get-Random -InputObject (get-content('.\AD_Users_Create\Names\femalenames-usa-top1000.txt'))
        $name = $givenname+"_"+$surname
    }
    $ouLocation = (Get-Random $OUsAll).distinguishedname
    if ((Get-Random -Maximum 100) -lt 50) {
        $pwd = Get-Random -InputObject (get-content '.\AD_Users_Create\wordlist.txt')
    } 
    else{
        $pwd = New-SWRandomPassword -MinPasswordLength 8 -MaxPasswordLength 10 
    }
    $aduserPassword =(ConvertTo-SecureString ($pwd) -AsPlainText -force)
    if ((Get-Random -Maximum 100) -lt 5 ){ $aduserdescription = 'Just so I dont forget my password is ' + $pwd } else {$aduserdescription =""}
    if ((Get-Random -Maximum 100) -lt 8 ){ $adacAccountNotDelegatedBool = $true } else { $adacAccountNotDelegatedBool = $false}
    if ((Get-Random -Maximum 100) -lt 3 ){ $adacPaswordNotRequiredBool = $true } else { $adacPaswordNotRequiredBool = $false}
    if ((Get-Random -Maximum 100) -lt 5 ){ $adacPasswordNeverExpiresBool = $true } else { $adacPasswordNeverExpiresBool = $false}
    if ((Get-Random -Maximum 100) -lt 3 ){ $adacCannotChangePasswordBool = $true } else { $adacCannotChangePasswordBool = $false}
    if ((Get-Random -Maximum 100) -lt 9 ){ $adacNoDelegationBool = $true } else { $adacNoDelegationBool = $false}
    if ((Get-Random -Maximum 100) -lt 6 ){ $adacTrustedToAuthDelegationBool = $true } else { $adacTrustedToAuthDelegationBool = $false}
    if (((Get-Random -Maximum 100) -lt 3 ) -and (!$adacPasswordNeverExpiresBool)) { $adacChangePassAtLogonBool = $true } else { $adacChangePassAtLogonBool = $false}
    if ((Get-Random -Maximum 100) -lt 8 ){ $adacReversibleEncryptionBool = $true } else { $adacReversibleEncryptionBool = $false}
    if ((Get-Random -Maximum 100) -lt 4 ){ $adacEnabledBool = $false } else { $adacEnabledBool = $true}
    if ((Get-Random -Maximum 100) -lt 4 ){ $adacSmartCardReqBool = $true } else { $adacSmartCardReqBool = $false}
    $aduserDepartment = Get-Random -InputObject (get-content '.\AD_Users_Create\Names\departments.txt')
    $aduserDepartmentNumber =Get-Random -Maximum 10000
    #$aduserTitle = Get-Random -InputObject (get-content '.\AD_Users_Create\Names\titles.txt')
    $aduserTitle = Get-Random -InputObject (get-content '.\AD_Users_Create\Names\titles-short.txt')
    $aduserEmpNum = Get-Random -Maximum 10000
    $aduserPOB = Get-Random -Maximum 10000
    $aduserPostalCode = Get-Random -Maximum 10000
    $aduserStreet = "Created with secframe.com/badblood."
    $aduserKerbrosenc = 'None','DES','RC4','AES128','AES256' | Get-Random 
    $aduserUPN = $name + '@' + $dnsroot

    new-aduser `
    -Server $setDC `
    -DisplayName $name -name $name -SamAccountName $name -Surname $surname -GivenName $givenname `
    -Enabled $adacEnabledBool `
    -Path $ouLocation `
    -AccountPassword $aduserPassword `
    -AccountNotDelegated  $adacAccountNotDelegatedBool `
    -AllowReversiblePasswordEncryption $adacReversibleEncryptionBool `
    -CannotChangePassword $adacCannotChangePasswordBool `
    -ChangePasswordAtLogon $adacChangePassAtLogonBool `
    -PasswordNeverExpires $adacPasswordNeverExpiresBool `
    -PasswordNotRequired $adacPaswordNotRequiredBool `
    -SmartcardLogonRequired $adacSmartCardReqBool `
    -TrustedForDelegation $adacTrustedToAuthDelegationBool `
    -KerberosEncryptionType $aduserKerbrosenc `
    -Department $aduserDepartment -Description $aduserdescription -Title $aduserTitle -EmployeeNumber $aduserEmpNum `
    -POBox $aduserPOB -PostalCode $aduserPostalCode -StreetAddress $aduserStreet `
    -UserPrincipalName $aduserUPN
     
    }