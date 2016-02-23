#########################################################################
# Active Directory Stale Computer Report Tool v2.2                      #
#                                                                       #
# Created by: Jordan LaFontaine 01/27/2016                              #
# Email: J.LaFontaine@snhu.edu                                          #
#                                                                       #
#                                                                       #
#                                                                       #
#                                                                       #
#########################################################################


Param(            
    [parameter(Mandatory=$true)]            
    $InputFilePath,
    [parameter(Mandatory=$true)]
    $MaxConcurrent,
    [parameter(Mandatory=$true)]
    $TimesToPing,
    $TimeoutInSeconds,
    $ResolveNames
    )


#Import the AD Module.
import-module activedirectory  

#Set domain, number of days to go back for lastLogonTimeStamp and pwdLastSet, today's time and date, date deletion will take place.  
$lastLogonTimeStampDaysInactive = 180
$pwdLastSetDaysInactive = 90
$lastLogonTimeStampDateFormat = (Get-Date).Adddays(-($lastLogonTimeStampDaysInactive))
$pwdLastSetDateFormat = (Get-Date).AddDays(-($pwdLastSetDaysInactive))

#Containers to be excluded
$VDI = "OU=SNHU VDI,DC=snhu,DC=edu"
$SS = "OU=SNHU Servers,DC=snhu,dc=edu"
$ES = "OU=Exchange Servers,DC=snhu,DC=edu"
$AS = "OU=Application Servers,OU=SNHU Servers,DC=snhu,DC=edu"
$DS = "OU=Datatel Servers,OU=SNHU Servers,DC=snhu,DC=edu"
$IS = "OU=Infrastructure Servers,OU=SNHU Servers,DC=snhu,DC=edu"
$SQLS = "OU=SQL Servers,OU=SNHU Servers,DC=snhu,DC=edu"
$EMAILS = "OU=E-Mail Servers,OU=SNHU Servers,DC=snhu,DC=edu"


function Gather-Computers

{

#Get all AD computers with lastLogonTimestamp and pwdLastSet less than our time 
Get-ADComputer -Filter {LastLogonTimeStamp -lt $lastLogonTimeStampDateFormat -and pwdLastSet -lt $pwdLastSetDateFormat} -Properties LastLogonTimeStamp, DistinguishedName |

#Filter Out any Objects Living in these OUs: 
?{
    ($_.distinguishedname -notmatch $VDI) -and
    ($_.distinguishedName -notmatch $SS) -and
    ($_.distinguishedName -notmatch $ES) -and
    ($_.distinguishedName -notmatch $AS) -and
    ($_.distinguishedName -notmatch $DS) -and
    ($_.distinguishedName -notmatch $IS) -and
    ($_.distinguishedName -notmatch $SQLS) -and
    ($_.distinguishedName -notmatch $EMAILS)
  
 } 
} 