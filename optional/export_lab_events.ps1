param(
    [Parameter(Mandatory=$true)][datetime]$StartTime,
    [Parameter(Mandatory=$true)][datetime]$EndTime,
    [string]$OutputPath = '.\windows-real.jsonl'
)
$ErrorActionPreference = 'Stop'
if ($env:COMPUTERNAME -ne 'DESKTOP-N7PEBGK') { throw 'Run only inside the documented Windows lab VM.' }
if ($EndTime -le $StartTime) { throw 'EndTime must follow StartTime.' }
if (Test-Path -LiteralPath $OutputPath) { throw 'Choose a new output filename.' }
$runId = 'windows-real-' + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$lines = @()
$records = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625; StartTime=$StartTime; EndTime=$EndTime}
foreach ($record in ($records | Sort-Object TimeCreated, RecordId)) {
    [xml]$xml = $record.ToXml()
    $fields = @{}
    foreach ($node in $xml.Event.EventData.Data) { $fields[$node.GetAttribute('Name')] = $node.InnerText }
    if ($fields['TargetUserName'] -notin @('LabUser','LabAdmin','UtenteInesistente')) { continue }
    $row = [ordered]@{
        timestamp=$record.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        EventCode=$record.Id; EventRecordID=$record.RecordId; Computer=$record.MachineName
        TargetDomainName=$fields['TargetDomainName']; TargetUserName=$fields['TargetUserName']
        SubjectUserName=$fields['SubjectUserName']; SourceIp=$fields['IpAddress']
        LogonType=$fields['LogonType']; Status=$fields['Status']; SubStatus=$fields['SubStatus']
        synthetic=$false; run_id=$runId; scenario_id='actual_lab'
        data_origin='normalized_from_windows_security_log'
    }
    $lines += ($row | ConvertTo-Json -Compress)
}
if ($lines.Count -eq 0) { throw 'No selected lab-account events in this interval.' }
[System.IO.File]::WriteAllLines([System.IO.Path]::GetFullPath($OutputPath), [string[]]$lines, (New-Object System.Text.UTF8Encoding($false)))
Write-Output "Exported $($lines.Count) REAL lab records, run_id=$runId. Original EVTX should be preserved separately."
