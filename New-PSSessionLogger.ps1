#!/usr/bin/env pwsh
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.IO.Pipes;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Threading;

namespace NaughtyPipe
{
    public class Delegator : IDisposable
    {
        private RunspacePool _runspacePool;
        private PipeStream _originRead;
        private PipeStream _originWrite;
        private PipeStream _targetRead;
        private PipeStream _targetWrite;
        private ScriptBlock _originDelegate;
        private ScriptBlock _targetDelegate;
        private Thread _readThread;
        private Thread _writeThread;

        public Delegator(PipeStream origin, ScriptBlock originDelegate,
            PipeStream target, ScriptBlock targetDelegate)
            : this(origin, origin, originDelegate, target, target, targetDelegate)
        { }

        public Delegator(PipeStream originRead, PipeStream originWrite, ScriptBlock originDelegate,
            PipeStream targetRead, PipeStream targetWrite, ScriptBlock targetDelegate)
        {
            if (!originRead.CanRead)
                throw new ArgumentException("Must be able to read from originRead");
            if (!originWrite.CanWrite)
                throw new ArgumentException("Must be able to write to originWrite");
            if (!targetRead.CanRead)
                throw new ArgumentException("Must be able to read from targetRead");
            if (!targetWrite.CanWrite)
                throw new ArgumentException("Must be able to write to targetWrite");

            _originRead = originRead;
            _originWrite = originWrite;
            _originDelegate = originDelegate;
            _targetRead = targetRead;
            _targetWrite = targetWrite;
            _targetDelegate = targetDelegate;

            _runspacePool = RunspaceFactory.CreateRunspacePool(2, 2);
        }

        public void Start()
        {
            _runspacePool.Open();
            _readThread = new Thread(() => Runner(_originRead, _targetWrite, _originDelegate));
            _readThread.Start();
            _writeThread = new Thread(() => Runner(_targetRead, _originWrite, _targetDelegate));
            _writeThread.Start();
        }

        public void Wait()
        {
            _readThread.Join();
            _writeThread.Join();
        }

        private void Runner(PipeStream readPipe, PipeStream writePipe, ScriptBlock delegateFunc)
        {
            try
            {
                using (StreamReader sr = new StreamReader(readPipe))
                using (StreamWriter sw = new StreamWriter(writePipe))
                {
                    while (true)
                    {
                        string line = line = sr.ReadLine();
                        if (String.IsNullOrEmpty(line))
                            break;

                        using (PowerShell pipeline = PowerShell.Create())
                        {
                            pipeline.RunspacePool = _runspacePool;
                            pipeline.AddScript(delegateFunc.ToString(), true);
                            pipeline.AddArgument(line);
                            pipeline.Invoke();
                        }

                        sw.WriteLine(line);
                        sw.Flush();
                    }
                }
            }
            catch (Exception e)
            {
                if (e is IOException || e is ObjectDisposedException)
                    return;

                throw;
            }
        }

        public void Dispose()
        {
            if (_readThread != null)
                _readThread.Join();
            if (_writeThread != null)
                _writeThread.Join();
            _runspacePool.Dispose();

            GC.SuppressFinalize(this);
        }
        ~Delegator() { this.Dispose(); }
    }
}
'@

# Used for custom host tests
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Management.Automation;
using System.Management.Automation.Host;
using System.Security;

namespace CustomPSHost
{
    public class Host : PSHost
    {
        private readonly PSHost PSHost;
        private readonly HostUI HostUI;

        public Host(PSHost host){
            PSHost=host;
            HostUI = new HostUI(PSHost.UI);
        }

        public override CultureInfo CurrentCulture => PSHost.CurrentCulture;

        public override CultureInfo CurrentUICulture => PSHost.CurrentUICulture;

        public override Guid InstanceId => PSHost.InstanceId;

        public override string Name => PSHost.Name;

        public override PSHostUserInterface UI => HostUI;

        public override Version Version => PSHost.Version;

        public override void EnterNestedPrompt()
        {
            PSHost.EnterNestedPrompt();
        }

        public override void ExitNestedPrompt()
        {
            PSHost.ExitNestedPrompt();
        }

        public override void NotifyBeginApplication()
        {
            PSHost.NotifyBeginApplication();
        }

        public override void NotifyEndApplication()
        {
            PSHost.NotifyEndApplication();
        }

        public override void SetShouldExit(int exitCode)
        {
            PSHost.SetShouldExit(exitCode);
        }
    }

    public class HostUI : PSHostUserInterface
    {
        private readonly PSHostUserInterface PSHostUI;

        public HostUI(PSHostUserInterface psHostUI) => PSHostUI = psHostUI;

        public override PSHostRawUserInterface RawUI => PSHostUI.RawUI;

        public override Dictionary<string, PSObject> Prompt(string caption, string message, Collection<FieldDescription> descriptions)
        {
            return PSHostUI.Prompt(caption, message, descriptions);
        }

        public override int PromptForChoice(string caption, string message, Collection<ChoiceDescription> choices, int defaultChoice)
        {
            return PSHostUI.PromptForChoice(caption, message, choices, defaultChoice);
        }

        public override PSCredential PromptForCredential(string caption, string message, string userName, string targetName, PSCredentialTypes allowedCredentialTypes, PSCredentialUIOptions options)
        {
            return PSHostUI.PromptForCredential(caption, message, userName, targetName, allowedCredentialTypes, options);
        }

        public override PSCredential PromptForCredential(string caption, string message, string userName, string targetName)
        {
            return PSHostUI.PromptForCredential(caption, message, userName, targetName);
        }

        public override string ReadLine()
        {
            //throw new Exception("test");
            return PSHostUI.ReadLine();
        }

        public override SecureString ReadLineAsSecureString()
        {
            return PSHostUI.ReadLineAsSecureString();
        }

        public override void Write(ConsoleColor foregroundColor, ConsoleColor backgroundColor, string value)
        {
            PSHostUI.Write(foregroundColor, backgroundColor, value);
        }

        public override void Write(string value)
        {
            PSHostUI.Write(value);
        }

        public override void WriteDebugLine(string message)
        {
            PSHostUI.WriteDebugLine(message);
        }

        public override void WriteErrorLine(string value)
        {
            PSHostUI.WriteErrorLine(value);
        }

        public override void WriteLine(string value)
        {
            //throw new Exception("test");
            PSHostUI.WriteLine(value);
        }

        public override void WriteProgress(long sourceId, ProgressRecord record)
        {
            PSHostUI.WriteProgress(sourceId, record);
        }

        public override void WriteVerboseLine(string message)
        {
            PSHostUI.WriteVerboseLine(message);
        }

        public override void WriteWarningLine(string message)
        {
            PSHostUI.WriteWarningLine(message);
        }
    }
}
'@


enum Destination {
    Client = 0x00000001
    Server = 0x00000002
}

enum MessageType {
    SESSION_CAPABILITY = 0x00010002
    INIT_RUNSPACEPOOL = 0x00010004
    PUBLIC_KEY = 0x00010005
    ENCRYPTED_SESSION_KEY = 0x00010006
    PUBLIC_KEY_REQUEST = 0x00010007
    CONNECT_RUNSPACEPOOL = 0x00010008
    RUNSPACEPOOL_INIT_DATA = 0x0002100B
    RESET_RUNSPACE_STATE = 0x0002100C
    SET_MAX_RUNSPACES = 0x00021002
    SET_MIN_RUNSPACES = 0x00021003
    RUNSPACE_AVAILABILITY = 0x00021004
    RUNSPACEPOOL_STATE = 0x00021005
    CREATE_PIPELINE = 0x00021006
    GET_AVAILABLE_RUNSPACES = 0x00021007
    USER_EVENT = 0x00021008
    APPLICATION_PRIVATE_DATA = 0x00021009
    GET_COMMAND_METADATA = 0x0002100A
    RUNSPACEPOOL_HOST_CALL = 0x00021100
    RUNSPACEPOOL_HOST_RESPONSE = 0x00021101
    PIPELINE_INPUT = 0x00041002
    END_OF_PIPELINE_INPUT = 0x00041003
    PIPELINE_OUTPUT = 0x00041004
    ERROR_RECORD = 0x00041005
    PIPELINE_STATE = 0x00041006
    DEBUG_RECORD = 0x00041007
    VERBOSE_RECORD = 0x00041008
    WARNING_RECORD = 0x00041009
    PROGRESS_RECORD = 0x00041010
    INFORMATION_RECORD = 0x00041011
    PIPELINE_HOST_CALL = 0x00041100
    PIPELINE_HOST_RESPONSE = 0x00041101
}


Function ConvertTo-PSSessionFragment {
    <#
    .SYNOPSIS
    Convert a raw PSRP fragment to an object.

    .PARAMETER InputObject
    The fragment(s) bytes.

    .EXAMPLE
    $rawFragment = [Convert]::FromBase64String($fragmentSource)
    ConvertTo-PSSessionFragment -InputObject $rawFragment

    .OUTPUTS
    PSSession.Fragment
        ObjectID = The unique identifier for a fragmented PSRP message.
        FragmentID = The unique identifier of the fragments in a fragmented PSRP message.
        Start = Whether this is the start PSRP message fragment for the ObjectID (PSRP Message).
        End = Whether this is the last PSRP message fragment for the ObjectID (PSRP Message).
        Blob = The PSRP message fragment bytes.

    .NOTES
    A raw fragment from a PSSession can contain 1, or multiple fragments which this cmdlet will output all of them.
    The structure of this fragment is documented in [MS-PSRP] 2.2.4 Packet Fragment
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/3610dae4-67f7-4175-82da-a3fab83af288.
    #>
    [OutputType('PSSession.Fragment')]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [byte[]]
        $InputObject
    )

    while ($InputObject) {
        # The integer values are in network binary order so we need to reverse the entries.
        [Array]::Reverse($InputObject, 0, 8)
        $objectId = [BitConverter]::ToUInt64($InputObject, 0)

        [Array]::Reverse($InputObject, 8, 8)
        $fragmentId = [BitConverter]::ToUInt64($InputObject, 8)

        $startEndByte = $InputObject[16]
        $start = [bool]($startEndByte -band 0x1)
        $end = [bool]($startEndByte -band 0x2)

        [Array]::Reverse($InputObject, 17, 4)
        $length = [BitConverter]::ToUInt32($InputObject, 17)
        [byte[]]$blob = $InputObject[21..(20 + $length)]

        $InputObject = $InputObject[(21 + $length)..($InputObject.Length)]

        if ($start -and $fragmentId -ne 0) {
            Write-Error -Message "Fragment $objectId start is expecting a fragment ID of 0 but got $fragmentId"
            continue
        }

        [PSCustomObject]@{
            PSTypeName = 'PSSession.Fragment'
            ObjectID = $objectId
            FragmentID = $fragmentId
            Start = $start
            End = $end
            Blob = $blob
        }
    }
}


Function ConvertTo-PSSessionMessage {
    <#
    .SYNOPSIS
    Convert a completed PSRP fragment to a PSRP message object.

    .PARAMETER InputObject
    The completed fragment bytes.

    .PARAMETER ObjectID
    The ObjectID of the fragment(s) the PSRP message belonged to.

    .EXAMPLE
    $rawFragment = [Convert]::FromBase64String($fragmentSource)
    ConvertTo-PSSessionFragment -InputObject $rawFragment | ForEach-Object {
        if ($_.Start -and $_.End) {
            ConvertTo-PSSessionMessage -InputObject $_.Blob -ObjectID $_.ObjectID
        }
    }

    .OUTPUTS
    PSSession.Message
        ObjectID = The unique identifier for the fragment the PSRP message belongs to.
        Destination = The destination of the message
        MessageType = The type of the message.
        RPID = The RunspacePool ID as a GUID the message targets.
        PID = The Pipeline ID as a GUID the message targets.
        Message = The parsed message as a PSObject.
        Raw = The raw CLIXML of the message as a string.

    .NOTES
    The structure of this message is documented in [MS-PSRP] 2.2.1 PowerShell Remoting Protocol Message.
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/497ac440-89fb-4cb3-9cc1-3434c1aa74c3
    #>
    [OutputType('PSSession.Message')]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [byte[]]
        $InputObject,

        [Parameter(Mandatory=$true)]
        [UInt64]
        $ObjectID
    )

    $destination = [Destination][BitConverter]::ToInt32($InputObject, 0)
    $messageType = [MessageType][BitConverter]::ToInt32($InputObject, 4)

    $rpIdBytes = $InputObject[8..23]
    $rpId = [Guid]::new([byte[]]$rpIdBytes)

    $psIdBytes = $InputObject[24..39]
    $psId = [Guid]::new([byte[]]$psIdBytes)

    # Handle if the blob contains the UTF-8 BOM or not.
    $startIdx = 40
    if ($InputObject[40] -eq 239 -and $InputObject[41] -eq 187 -and $InputObject[42] -eq 191) {
        $startIdx = 43
    }
    [byte[]]$dataBytes = $InputObject[$startIdx..$InputObject.Length]
    $message = [Text.Encoding]::UTF8.GetString($dataBytes)

    $tmpPath = [IO.Path]::GetTempFileName()
    try {
        Set-Content -LiteralPath $tmpPath -Value @"
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
$message
</Objs>
"@
        $psObject = Import-Clixml -LiteralPath $tmpPath
    }
    finally {
        Remove-Item -Path $tmpPath
    }

    # Make our CLIXML pretty with indents so it can be easily parsed by a human
    $stringWriter = [IO.StringWriter]::new()
    $xmlWriter = $null
    try {
        $xmlWriter = [Xml.XmlTextWriter]::new($stringWriter)
        $xmlWriter.Formatting = [Xml.Formatting]::Indented
        $xmlWriter.Indentation = 2
        ([xml]$message).WriteContentTo($xmlWriter)
        $xmlWriter.Flush()
        $stringWriter.Flush()

        $prettyXml = $stringWriter.ToString()
    }
    finally {
        if ($xmlWriter) {
            $xmlWriter.Dispose()
        }
        $stringWriter.Dispose()
    }

    [PSCustomObject]@{
        PSTypeName = 'PSSession.Message'
        ObjectID = $ObjectID
        Destination = $destination
        MessageType = $messageType
        RPID = $rpId
        PID = $psId
        Message = $psObject
        Raw = $prettyXml
    }
}


Function ConvertTo-PSSessionPacket {
    <#
    .SYNOPSIS
    Parse the PSRP packets generated by New-PSSessionLogger into a rich PSObject.

    .PARAMETER InputObject
    The OutOfProc PSRP XML packet to convert.

    .EXAMPLE
    $log = 'C:\temp\pssession.log'
    Remove-Item -Path $log -ErrorAction SilentlyContinue

    $session = New-PSSessionLogger -LogPath $log
    try {
        Invoke-Command -Session $session -ScriptBlock { echo "hi" }
    }
    finally {
        $session | Remove-PSSession
    }
    Get-Content -Path $log | ConvertTo-PSSessionPacket

    .OUTPUTS
    PSSession.Packet
        Type = The OutOfProc XML element type.
        PSGuid = The PSGuid assigned to the packet
        Stream = The stream of the packet (only when Type -eq 'Data')
        Fragments = The fragments contains in the packet (only when Type -eq 'Data')
        Messages = The completed PSRP messages in the fragments (only when Type -eq 'Data')
        Raw = The raw OutOfProc XML value.
    #>
    [OutputType('PSSession.Packet')]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [String[]]
        $InputObject
    )

    begin {
        $fragmentBuffer = @{}
    }

    process {
        foreach ($packet in $InputObject) {
            $xmlData = ([xml]$packet).DocumentElement
            $fragments = $null
            $messages = $null

            if ($xmlData.Name -eq 'Data') {
                $rawFragment = [Convert]::FromBase64String($xmlData.'#text')

                $fragments = ConvertTo-PSSessionFragment -InputObject $rawFragment
                $messages = $fragments | ForEach-Object -Process {
                    if ($_.Start) {
                        $fragmentBuffer.($_.ObjectID) = [Collections.Generic.List[Byte]]@()
                    }

                    $buffer = $fragmentBuffer.($_.ObjectID)
                    $buffer.AddRange($_.Blob)

                    if ($_.End) {
                        $fragmentBuffer.Remove($_.ObjectID)
                        ConvertTo-PSSessionMessage -InputObject $buffer -ObjectID $_.ObjectID
                    }
                }
            }

            [PSCustomObject]@{
                PSTypeName = 'PSSession.Packet'
                Type = $xmlData.Name
                PSGuid = $xmlData.PSGuid
                Stream = $xmlData.Stream
                Fragments = $fragments
                Messages = $messages
                Raw = $packet
            }
        }
    }

    end {
        foreach ($kvp in $fragmentBuffer.GetEnumerator()) {
            Write-Warning -Message "Incomplete buffer for fragment $($kvp.Key)"
        }
    }
}


Function Watch-PSSessionLog {
    <#
    .SYNOPSIS
    Watches a PSSession logging file and outputs parsed PSSession packets as they come in.

    .PARAMETER Path
    The log file to watch.

    .PARAMETER ScanHistory
    Process any existing entries in the log file before waiting for new events.

    .PARAMETER Wait
    Keep on reading the log file even once a session has closed.

    .EXAMPLE
    Watch-PSSessionLog -Path C:\temp\pssession.log
    #>
    [OutputType('PSSession.Packet')]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [String]
        $Path,

        [Switch]
        $ScanHistory,

        [Switch]
        $Wait
    )

    process {
        $gcParams = @{
            LiteralPath = $Path
            Wait = $Wait.IsPresent
        }
        if (-not $ScanHistory) {
            $gcParams.Tail = 0
        }
        Get-Content @gcParams | ConvertTo-PSSessionPacket
    }
}


Function Format-PSSessionPacket {
    <#
    .SYNOPSIS
    Formats a PSSession.Packet to a more human friendly output.

    .PARAMETER InputObject
    The PSSession.Packet object to format.

    .EXAMPLE
    Watch-PSSessionLog -Path C:\temp\pssession.log | Format-PSSessionPacket
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [PSTypeName('PSSession.Packet')]
        $InputObject
    )

    process {
        # The properties are padded to the length of the longest property
        $padding = "Fragments".Length + 1
        $valuePadding = " " * ($padding + 2)
        $formatComplexValue = {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
                $InputObject,

                [int]
                $PaddingLength = 0
            )
            $padding = " " * $PaddingLength

            # Get the length of the longest property
            $propertyPadding = 0
            foreach ($prop in $InputObject.PSObject.Properties.Name) {
                if ($prop.Length -gt $propertyPadding) {
                    $propertyPadding = $prop.Length
                }
            }

            $sb = [Text.StringBuilder]::new()
            foreach ($prop in $InputObject.PSObject.Properties) {
                $formattedValue = $prop.Value

                if ('System.Management.Automation.PSCustomObject' -in $formattedValue.PSTypeNames) {
                    $formattedValue = @($formattedValue)
                }

                if ($formattedValue -is [Array]) {
                    $formattedValue = foreach ($entry in $formattedValue) {
                        if ($entry -is [PSCustomObject]) {
                            $valuePadding = $propertyPadding + 3
                            $entry = foreach ($subEntry in $entry) {
                                ($subEntry | &$formatComplexValue -PaddingLength $valuePadding).Trim()
                            }

                            $entry = $entry -join "`n"
                        }

                        $entry.Trim()
                    }

                    $formattedValue = $formattedValue -join ("`n`n" + " " * $valuePadding)
                }

                $null = $sb.
                    Append($padding).
                    Append($prop.Name).
                    Append(" " * ($propertyPadding - $prop.Name.Length)).
                    Append(" : $formattedValue`n")
            }

            $sb.ToString()
        }

        $obj = $InputObject | Select-Object -Property @(
            'Type',
            @{ N = 'PSGuid'; E = { $_.PSGuid.ToString() } },
            'Stream',
            @{
                N = 'Fragments'
                E = {
                    @($_.Fragments | Select-Object -Property @(
                        'ObjectID',
                        'FragmentID',
                        'Start',
                        'End',
                        @{ N = 'Length'; E = { $_.Blob.Length } }
                    ))
                }
            },
            @{
                N = 'Messages'
                E = {
                    @($_.Messages | Select-Object -Property @(
                        'ObjectID',
                        'Destination',
                        'MessageType',
                        @{ N = 'RPID'; E = { $_.RPID.ToString() } },
                        @{ N = 'PID'; E = { $_.PID.ToString() } },
                        @{ N = 'Object'; E = { "`n" + $_.Raw } }
                    ))
                }
            }
        )

        $msg = $obj | &$formatComplexValue
        Write-Host $msg
    }
}


Function New-PSSessionLogger {
    <#
    .SYNOPSIS
    Create a new PSSession that logs the PSRP data packets.

    .PARAMETER FilePath
    Create a new PowerShell process to attach to as the PSSession target. Other use -Name to attach to an existing
    bidirectional named pipe.

    .PARAMETER ArgumentList
    Optional arguments when starting a new process.

    .PARAMETER Name
    Instead of starting a new process, attach the PSSession to the named pipe specified. This must be a bidirectional
    pipe that can send and receive PSRP packets.

    .PARAMETER LogPath
    The path to log the PSRP packets exchanged between the client and server.

    .EXAMPLE Open a logged session to Windows PowerShell
    $session = New-PSSessionLogger -LogPath pssession.log
    Invoke-Command -Session $session -ScriptBlock { $PSVersionTable }
    $session.Dispose()

    .EXAMPLE Open a logged session to PowerShell
    $session = New-PSSessionLogger -LogPath pssession.log -FilePath pwsh
    Invoke-Command -Session $session -ScriptBlock { $PSVersionTable }
    $session.Dispose()

    .OUTPUTS PSSession
    This is a PSSession object that can be used with Enter-PSSession/Invoke-Command. Make sure you call the
    '.Dispose()' method on this object to clean up any resources running in the background.

    .NOTES
    This is a proof of concept and not really safe at all. Requires PowerShell 6+. Make sure you call .Dispose
    #>
    [OutputType([Management.Automation.Runspaces.PSSession])]
    [CmdletBinding(DefaultParameterSetName='Process')]
    param (
        [Parameter(Mandatory=$true)]
        [String]
        $LogPath,

        [Parameter(ParameterSetName='Process')]
        [String]
        $FilePath = 'powershell',

        [Parameter(ParameterSetName='Process')]
        [String[]]
        $ArgumentList = @('-NoProfile', '-NoLogo'),

        [Parameter(ParameterSetName='Pipe')]
        [String]
        $Name
    )

    # The delegate is run in a separate runspace so it doesn't have access to our vars.
    $onLine = [ScriptBlock]::Create(@'
[CmdletBinding()]
param ([String]$Data)

Add-Content -LiteralPath '{0}' -Value $Data
'@ -f $LogPath)

    $process = $null
    $disposables = [Collections.Generic.List[PSObject]]@()
    try {
        if ($PSCmdlet.ParameterSetName -eq 'Process') {
            if (-not $Name) {
                $Name = "PSHost.$([Guid]::NewGuid())"
            }
            $ArgumentList += @('-CustomPipeName', $Name)

            if ($PSVersionTable.Platform -eq 'Unix') {
                if ($FilePath -eq 'powershell') {
                    $FilePath = 'pwsh'
                }
                $psi = [Diagnostics.ProcessStartInfo]@{
                    FileName = 'nohup'
                    Arguments = "$FilePath $($ArgumentList -join ' ')"
                    RedirectStandardError = $true
                    RedirectStandardInput = $true
                    RedirectStandardOutput = $true
                }
                $netProcess = [Diagnostics.Process]::Start($psi)
                # While the buffer will fill up if we don't get the data this step shouldn't generate anything.
                # $netProcess.Add_OutputDataReceived({})
                # $newProcess.Add_ErrorDataReceived({})

                $process = Get-Process -Id $netProcess.Id
            }
            else {
                $processParams = @{
                    FilePath = $FilePath
                    ArgumentList = $ArgumentList
                    PassThru = $true
                    WindowStyle = 'Hidden'
                }
                $process = Start-Process @processParams
            }
        }

        # This is the InOut pipe of the peer we want to connect to.
        $targetPipe = [IO.Pipes.NamedPipeClientStream]::new(
            '.',
            $Name,
            [IO.Pipes.PipeDirection]::InOut,
            [IO.Pipes.PipeOptions ]::Asynchronous
        )
        $targetPipe.Connect()
        $disposables.Add($targetPipe)

        # This is our intermediate pipe that our PSSession connects to and then forwards onto targetPipe.
        $pipeName = 'Naughty-{0}' -f [Guid]::NewGuid()
        $naughtyPipe = [IO.Pipes.NamedPipeServerStream]::new(
            $pipeName,
            [IO.Pipes.PipeDirection]::InOut,
            1,
            [IO.Pipes.PipeTransmissionMode]::Byte,
            [IO.Pipes.PipeOptions ]::Asynchronous
        )
        $disposables.Add($naughtyPipe)
        $naughtyPipeWait = $naughtyPipe.BeginWaitForConnection($null, $null)

        # Use a custom PSHost to test out host method invocations.
        $customHost = [CustomPSHost.Host]::new($Host)

        # Runspace has OpenAsync but it does not have an waitable result so we run the blocking version in a separate
        # pipeline. This Runspace targets our intermediate pipe which then forwards to the target pipe.
        $ps = [PowerShell]::Create()
        $disposables.Add($ps)
        $null = $ps.AddScript({
            #$applicationArguments = @{
            #    Test = ('a' * 128KB)
            #}
            $applicationArguments = $null
            $connInfo = [Management.Automation.Runspaces.NamedPipeConnectionInfo]::new($args[0])
            $rs = [RunspaceFactory]::CreateRunspace($connInfo, $args[1], $null, $applicationArguments)
            $rs.Open()
            $rs
        }).AddArgument($pipeName).AddArgument($customHost)
        $rsConnectWait = $ps.BeginInvoke()

        # Now the Runspace open is running in the background we can wait until it's connected.
        $naughtyPipe.EndWaitForConnection($naughtyPipeWait)
        $delegator = [NaughtyPipe.Delegator]::new($naughtyPipe, $onLine, $targetPipe, $onLine)
        $disposables.Add($delegator)
        $delegator.Start()

        # Get the Runspace and use reflection to build a PSSession object from it.
        $rs = $ps.EndInvoke($rsConnectWait)[0]
        $rs = $rs -as $rs.GetType()  # EndInvoke() returns as a PSObject and the constructor chokes on that.
        $cstr = [Management.Automation.Runspaces.PSSession].GetConstructor(
            'NonPublic, Instance', $null, [type[]]$rs.GetType(), $null)
        $session = $cstr.Invoke(@($rs))

        # Add a .Dispose() method that disposes of our resources.
        $disposeParams = @{
            Name = 'Dispose'
            MemberType = 'ScriptMethod'
            Value = {
                $session | Remove-PSSession
                Add-Content -Path $LogPath -Value ''

                if ($process) {
                    $process | Stop-Process -Force
                }

                $delegator.Dispose()
                $naughtyPipe.Dispose()
                $targetPipe.Dispose()
            }.GetNewClosure()
        }
        $session | Add-Member @disposeParams -PassThru
    }
    catch {
        if ($process) {
            $process | Stop-Process -Force
        }
        foreach ($waste in $disposables) {
            $waste.Dispose()
        }

        throw
    }
}
