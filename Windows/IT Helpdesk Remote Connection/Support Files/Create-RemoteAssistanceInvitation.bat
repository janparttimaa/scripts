@echo off
:: IT Helpdesk Remote Connection [Version 20251102]
:: (c) Jan Parttimaa. All rights reserved.
:: 
:: Replace "Example" with your company name e.g. Contoso
set COMPANY=Example
title %COMPANY% IT Helpdesk Remote Connection
powershell.exe -ExecutionPolicy Bypass -File ".\Create-RemoteAssistanceInvitation.ps1"