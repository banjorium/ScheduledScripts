#########################################################################
# Active Directory Stale Computer Object Removal Tool v2.4              #
#                                                                       #
# Created by: Jordan LaFontaine 01/27/2016                              #
# Email: J.LaFontaine@snhu.edu                                          #
#                                                                       #
# Be sure to run Script A and B before executing this script.           #
#                                                                       #
# Script references OldComputers.TXT and produces DeletedComputers.TXT  #
#########################################################################



Import-Module ActiveDirectory 

$date = Get-Date

$SourceFile = Read-Host "Please Enter Path to DistinguishedNames.txt"
$Computer = get-content $SourceFile


ForEach ($Name in $Computer) 
{   Try {
        Remove-ADComputer $Name -ErrorAction Stop -Confirm:$false -Verbose
        Add-Content "C:\Users\j.lafontaine\Desktop\computer removal objects\DeletedComputers_$date.txt" -Value "$Name removed"
 
    }
    Catch {
        Add-Content 'C:\users\j.lafontaine\Desktop\computer removal objects\DeletedComputers_$date.txt' -Value "$Name not found because $($Error[0])"
    }
 
}