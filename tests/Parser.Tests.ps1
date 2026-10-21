#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-WinSecTestModule

    $script:Xml4625 = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>
    <EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode>
    <Keywords>0x8010000000000000</Keywords>
    <TimeCreated SystemTime="2026-10-10T03:04:05.1234567Z"/>
    <EventRecordID>424242</EventRecordID>
    <Correlation ActivityID="{11111111-2222-3333-4444-555555555555}"/>
    <Execution ProcessID="732" ThreadID="840"/>
    <Channel>Security</Channel><Computer>SRV01.corp.contoso.com</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-0-0</Data><Data Name="SubjectUserName">SRV01</Data>
    <Data Name="SubjectDomainName">CORP</Data><Data Name="SubjectLogonId">0x3e7</Data>
    <Data Name="TargetUserSid">S-1-0-0</Data><Data Name="TargetUserName">alice</Data>
    <Data Name="TargetDomainName">CORP</Data><Data Name="Status">0xc000006d</Data>
    <Data Name="FailureReason">%%2313</Data><Data Name="SubStatus">0xc000006a</Data>
    <Data Name="LogonType">3</Data><Data Name="LogonProcessName">NtLmSsp</Data>
    <Data Name="AuthenticationPackageName">NTLM</Data><Data Name="WorkstationName">WKS-77</Data>
    <Data Name="TransmittedServices">-</Data><Data Name="LmPackageName">-</Data>
    <Data Name="KeyLength">0</Data><Data Name="ProcessId">0x0</Data><Data Name="ProcessName">-</Data>
    <Data Name="IpAddress">203.0.113.7</Data><Data Name="IpPort">55123</Data>
  </EventData>
</Event>
'@

    $script:Xml1149 = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-TerminalServices-RemoteConnectionManager" Guid="{c76baa63-ae81-421c-b425-340b4b24157f}"/>
    <EventID>1149</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode>
    <Keywords>0x1000000000000000</Keywords>
    <TimeCreated SystemTime="2026-10-10T04:00:00.0000000Z"/>
    <EventRecordID>241</EventRecordID>
    <Correlation ActivityID="{f4206c2f-b0bf-4c54-aad2-c7d2769b0000}"/>
    <Execution ProcessID="10680" ThreadID="14208"/>
    <Channel>Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational</Channel>
    <Computer>HLPC01</Computer><Security UserID="S-1-5-20"/>
  </System>
  <UserData>
    <EventXML xmlns="Event_NS">
      <Param1>john.doe</Param1><Param2/><Param3>192.168.180.57</Param3>
    </EventXML>
  </UserData>
</Event>
'@

    $script:XmlLsm21 = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-TerminalServices-LocalSessionManager" Guid="{5d896912-022d-40aa-a3a8-4fa5515c76d7}"/>
    <EventID>21</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode>
    <Keywords>0x1000000000000000</Keywords>
    <TimeCreated SystemTime="2026-10-10T04:00:05.0000000Z"/>
    <EventRecordID>1520</EventRecordID>
    <Correlation ActivityID="{f4204024-08a2-45cd-951b-f756f64b0000}"/>
    <Execution ProcessID="1440" ThreadID="18112"/>
    <Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel>
    <Computer>HLPC01</Computer><Security UserID="S-1-5-18"/>
  </System>
  <UserData>
    <EventXML xmlns="Event_NS">
      <User>HLPC01\john.doe</User><SessionID>4</SessionID><Address>192.168.180.57</Address>
    </EventXML>
  </UserData>
</Event>
'@

    $script:Xml5156 = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>
    <EventID>5156</EventID><Version>1</Version><Level>0</Level><Task>12810</Task><Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-10-10T05:00:00.0000000Z"/>
    <EventRecordID>900</EventRecordID><Correlation/>
    <Execution ProcessID="4" ThreadID="400"/>
    <Channel>Security</Channel><Computer>FW01</Computer><Security/>
  </System>
  <EventData>
    <Data Name="ProcessId">4</Data><Data Name="Application">System</Data>
    <Data Name="Direction">%%14592</Data><Data Name="SourceAddress">203.0.113.7</Data>
    <Data Name="SourcePort">4444</Data><Data Name="DestAddress">10.1.2.3</Data>
    <Data Name="DestPort">445</Data><Data Name="Protocol">6</Data>
    <Data Name="LayerName">%%14610</Data><Data Name="LayerRTID">44</Data>
  </EventData>
</Event>
'@

    $script:XmlSysmon3 = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"/>
    <EventID>3</EventID><Version>5</Version><Level>4</Level><Task>3</Task><Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2026-10-10T06:00:00.0000000Z"/>
    <EventRecordID>77</EventRecordID><Correlation/>
    <Execution ProcessID="2200" ThreadID="2400"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WKS-12</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data><Data Name="UtcTime">2026-10-10 06:00:00.000</Data>
    <Data Name="ProcessGuid">{a1b2c3d4-0000-0000-0000-000000000000}</Data><Data Name="ProcessId">4321</Data>
    <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="User">CORP\bob</Data><Data Name="Protocol">tcp</Data><Data Name="Initiated">true</Data>
    <Data Name="SourceIsIpv6">false</Data><Data Name="SourceIp">10.1.2.99</Data>
    <Data Name="SourceHostname">WKS-12.corp.contoso.com</Data><Data Name="SourcePort">51234</Data>
    <Data Name="DestinationIsIpv6">false</Data><Data Name="DestinationIp">203.0.113.7</Data>
    <Data Name="DestinationHostname">bad.example</Data><Data Name="DestinationPort">443</Data>
  </EventData>
</Event>
'@

    $script:Xml7045 = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-ServiceControlManager" Guid="{555908d1-a6d7-4695-8e1e-26931d2012f4}"/>
    <EventID>7045</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode>
    <Keywords>0x8080000000000000</Keywords>
    <TimeCreated SystemTime="2026-10-10T07:00:00.0000000Z"/>
    <EventRecordID>31337</EventRecordID><Correlation/>
    <Execution ProcessID="800" ThreadID="3000"/>
    <Channel>System</Channel><Computer>SRV02</Computer><Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data>WinSvcX</Data><Data>C:\Windows\Temp\svc.exe</Data>
    <Data>own process</Data><Data>auto start</Data><Data>LocalSystem</Data>
  </EventData>
</Event>
'@

    $script:Xml4776ok = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>
    <EventID>4776</EventID><Version>0</Version><Level>0</Level><Task>14336</Task><Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-10-10T08:00:00.0000000Z"/>
    <EventRecordID>111</EventRecordID><Correlation/>
    <Execution ProcessID="732" ThreadID="800"/>
    <Channel>Security</Channel><Computer>DC01</Computer><Security/>
  </System>
  <EventData>
    <Data Name="PackageName">MICROSOFT_AUTHENTICATION_PACKAGE_V1_0</Data>
    <Data Name="TargetUserName">alice</Data><Data Name="Workstation">WKS-9</Data>
    <Data Name="ErrorCode">0x0</Data>
  </EventData>
</Event>
'@
}

Describe 'Event parser (ConvertTo-WinSecEvent)' {
    It 'Parses Security 4625 with full authentication context' {
        InModuleScope WinSecHunter -Parameters @{ Xml = $Xml4625 } { param($Xml)
            $e = ConvertTo-WinSecEvent -Record ([xml]$Xml)
            $e.EventId | Should -Be 4625
            $e.RecordId | Should -Be 424242
            $e.Computer | Should -Be 'SRV01.corp.contoso.com'
            $e.LogName | Should -Be 'Security'
            $e.TimeUtc.ToString('o') | Should -BeLike '2026-10-10T03:04:05.1234567*'
            $e.SourceIp | Should -Be '203.0.113.7'
            $e.SourcePort | Should -Be 55123
            $e.TargetAccount | Should -Be 'CORP\alice'
            $e.SubjectAccount | Should -Be 'CORP\SRV01'
            $e.LogonType | Should -Be ([WinSecLogonType]::Network)
            $e.AuthPackage | Should -Be 'NTLM'
            $e.Workstation | Should -Be 'WKS-77'
            $e.Outcome | Should -Be ([WinSecOutcome]::Failure)
            $e.Category | Should -Be ([WinSecEventCategory]::Authentication)
            $e.Importance | Should -Be ([WinSecSeverity]::Critical)
            $e.AttackIds | Should -Contain 'T1110.001'
            $e.StatusCode | Should -Match 'Incorrect password'
            $e.FailureReason | Should -Be '%%2313'
            $e.Data['ActivityID'] | Should -Be '{11111111-2222-3333-4444-555555555555}'
            $e.GetDedupKey() | Should -Match 'SRV01\.corp\.contoso\.com\|Security\|424242\|4625'
        }
    }

    It 'Parses RDP RCM 1149 UserData (Param1/2/3) layout' {
        InModuleScope WinSecHunter -Parameters @{ Xml = $Xml1149 } { param($Xml)
            $e = ConvertTo-WinSecEvent -Record ([xml]$Xml)
            $e.EventId | Should -Be 1149
            $e.SourceIp | Should -Be '192.168.180.57'
            $e.TargetAccount | Should -Be 'john.doe'
            $e.Outcome | Should -Be ([WinSecOutcome]::Success)
            $e.Category | Should -Be ([WinSecEventCategory]::RemoteAccess)
            $e.Data['ActivityID'] | Should -Be '{f4206c2f-b0bf-4c54-aad2-c7d2769b0000}'
        }
    }

    It 'Parses RDP LSM 21 UserData (User/SessionID/Address)' {
        InModuleScope WinSecHunter -Parameters @{ Xml = $XmlLsm21 } { param($Xml)
            $e = ConvertTo-WinSecEvent -Record ([xml]$Xml)
            $e.SourceIp | Should -Be '192.168.180.57'
            $e.TargetAccount | Should -Be 'HLPC01\john.doe'
            $e.Data['SessionID'] | Should -Be '4'
            $e.Outcome | Should -Be ([WinSecOutcome]::Success)
        }
    }

    It 'Parses firewall 5156: direction, protocol, both endpoints' {
        InModuleScope WinSecHunter -Parameters @{ Xml = $Xml5156 } { param($Xml)
            $e = ConvertTo-WinSecEvent -Record ([xml]$Xml)
            $e.SourceIp | Should -Be '203.0.113.7'
            $e.DestinationIp | Should -Be '10.1.2.3'
            $e.DestinationPort | Should -Be 445
            $e.Direction | Should -Be ([WinSecDirection]::Inbound)
            $e.Protocol | Should -Be 'TCP'
            $e.Category | Should -Be ([WinSecEventCategory]::NetworkActivity)
        }
    }

    It 'Parses Sysmon EID 3 with Initiated → Outbound' {
        InModuleScope WinSecHunter -Parameters @{ Xml = $XmlSysmon3 } { param($Xml)
            $e = ConvertTo-WinSecEvent -Record ([xml]$Xml)
            $e.SourceIp | Should -Be '10.1.2.99'
            $e.DestinationIp | Should -Be '203.0.113.7'
            $e.Direction | Should -Be ([WinSecDirection]::Outbound)
            $e.Category | Should -Be ([WinSecEventCategory]::NetworkActivity)
            $e.Importance | Should -Be ([WinSecSeverity]::Critical)
            $e.AttackIds | Should -Contain 'T1071'
            $e.ProcessName | Should -Match 'powershell'
        }
    }

    It 'Maps positional (unnamed) data for System log 7045' {
        InModuleScope WinSecHunter -Parameters @{ Xml = $Xml7045 } { param($Xml)
            $e = ConvertTo-WinSecEvent -Record ([xml]$Xml)
            $e.EventId | Should -Be 7045
            $e.LogName | Should -Be 'System'
            $e.ServiceName | Should -Be 'WinSvcX'
            $e.Data['ImagePath'] | Should -Be 'C:\Windows\Temp\svc.exe'
            $e.Category | Should -Be ([WinSecEventCategory]::ServiceActivity)
            $e.AttackIds | Should -Contain 'T1543.003'
        }
    }

    It 'Derives outcome from NTLM 4776 error code' {
        InModuleScope WinSecHunter -Parameters @{ Xml = $Xml4776ok } { param($Xml)
            $e = ConvertTo-WinSecEvent -Record ([xml]$Xml)
            $e.Outcome | Should -Be ([WinSecOutcome]::Success)
            $bad = $Xml -replace '0x0<', '0xC000006A<'
            $e2 = ConvertTo-WinSecEvent -Record ([xml]$bad)
            $e2.Outcome | Should -Be ([WinSecOutcome]::Failure)
            $e2.StatusCode | Should -Match 'Incorrect password'
        }
    }

    It 'Tolerates unknown event IDs gracefully' {
        InModuleScope WinSecHunter -Parameters @{ Xml = $Xml4625 } { param($Xml)
            $x = $Xml -replace '>4625<', '>9999<'
            $e = ConvertTo-WinSecEvent -Record ([xml]$x)
            $e.Category | Should -Be ([WinSecEventCategory]::Unknown)
            $e.Outcome | Should -Be ([WinSecOutcome]::Unknown)
            $e.EventName | Should -Be 'Event 9999'
        }
    }

    It 'Consumes remote payload hashtables and honors authoritative UTC' {
        InModuleScope WinSecHunter -Parameters @{ Xml = $Xml4625 } { param($Xml)
            $utc = [datetime]::SpecifyKind([datetime]'2026-10-10 12:00:00', [System.DateTimeKind]::Utc)
            $payload = @{ Xml = $Xml; Computer = 'SRV01'; RecordId = 424242L; TimeUtc = $utc; LogName = 'Security'; Message = 'rendered message' }
            $e = ConvertTo-WinSecEvent -Record $payload -IncludeMessage
            $e.TimeUtc.ToString('yyyy-MM-dd HH:mm:ss') | Should -Be '2026-10-10 12:00:00'
            $e.Message | Should -Be 'rendered message'
        }
    }

    It 'Attaches raw XML with -IncludeRawXml' {
        InModuleScope WinSecHunter -Parameters @{ Xml = $Xml4625 } { param($Xml)
            $e = ConvertTo-WinSecEvent -Record ([xml]$Xml) -IncludeRawXml
            $e.Xml | Should -Match '<Event'
            $e.ToHashtable($true)['Data_IpAddress'] | Should -Be '203.0.113.7'
        }
    }
}
