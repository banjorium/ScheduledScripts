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
