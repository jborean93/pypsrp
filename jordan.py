import asyncio
import typing

from psrp.connection_info import (
    AsyncProcessInfo,
    AsyncWSManInfo,
)

from psrp.dotnet.complex_types import (
    ConsoleColor,
    Coordinates,
    Size,
)

from psrp.dotnet.primitive_types import (
    PSSecureString,
)

from psrp.host import (
    PSHost,
    PSHostUI,
    PSHostRawUI,
)

from psrp.powershell import (
    AsyncCommandMetaPipeline,
    AsyncPowerShell,
    AsyncRunspacePool,
)

from psrp.protocol.powershell import (
    Command,
    PipelineResultTypes,
)


endpoint = 'dc01.domain.test'

script = '''
param (
    [Parameter(ValueFromPipeline=$true)]
    $InputObject
)

begin {
    "begin"
    
    $DebugPreference = 'Continue'
    $InformationPreference = 'Continue'
    $VerbosePreference = 'Continue'
    $WarningPreference = 'Continue'
}
process {
    "process"
    "input: '$InputObject'"
}
end {
    #sleep 0
    #Write-Progress -Activity 'Stream Output' -Status 'Some status' -PercentComplete 10
    #Write-Debug debug
    #Write-Information information
    #Write-Verbose verbose
    #Write-Warning warning
    #Write-Progress -Activity 'Stream Output' -Status 'Finished' -PercentComplete 100

    "end"
    #$Host.EnterNestedPrompt()
    #$Host.UI.RawUI.BackgroundColor = 'Red'
    #$Host.UI.RawUI.CursorPosition = [Management.Automation.Host.Coordinates]::new(1, 2)
    #$host.UI.RawUI.WindowSize = [Management.Automation.Host.Size]::new(1024, 1024)
    #$Host.SetShouldExit(1)
    
    #$choices = [Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]]::new()
    #$choices.Add([Management.Automation.Host.ChoiceDescription]::new('description'))

    $host.UI.PromptForChoice('caption', 'message', $choices, 0)
    #$host.UI.ReadLine()
    #ls /tmp/test
    #"finished host"
}
'''


async def async_psrp(connection_info):
    class AsyncPSHost(PSHost):

        async def get_host_info(self):
            return super().get_host_info()

    class AsyncHostUI(PSHostUI):

        async def prompt_for_choice(self, *args, **kwargs):
            raise Exception('fuck you')
        
        async def write_progress(self, source_id, record):
            return

    class AsyncHostRawUI(PSHostRawUI):

        def get_foreground_color(self) -> ConsoleColor:
            return ConsoleColor.White

        def get_background_color(self) -> ConsoleColor:
            return ConsoleColor.Black

        def get_cursor_position(self) -> Coordinates:
            return Coordinates(0, 0)

        def get_window_position(self):
            return Coordinates(0, 0)

        def get_cursor_size(self):
            return 0

        def get_buffer_size(self):
            return Size(10, 10)

        def get_window_size(self):
            return Size(10, 10)

        def get_max_window_size(self):
            return Size(10, 10)

        def get_max_physical_window_size(self):
            return Size(10, 10)

        def get_window_title(self):
            return 'My Title'

    host = AsyncPSHost(ui=AsyncHostUI(raw_ui=AsyncHostRawUI()))

    async with AsyncRunspacePool(connection_info, host=host) as rp:
        #meta = AsyncCommandMetaPipeline(rp, 'Invoke*')
        #async for meta_out in meta.invoke():
        #    if not hasattr(meta_out, 'Name'):
        #        continue

        #    print(f'Meta: {meta_out.Name}')

        #await rp.exchange_key()
        
        ps = AsyncPowerShell(rp)
        ps.add_script(script)

        async def read_stream(name):
            test = []
            stream = ps.streams[name]
            while True:
                obj = await stream.wait()
                if obj is None:
                    break

                test.append(obj)

                print(f"{name} - {obj!s}")

            return test

        read = asyncio.create_task(read_stream('progress'))

        async def async_generator():
            yield 1
            yield 2
            yield PSSecureString('abc')

        task = await ps.begin_invoke(async_generator())
        #await asyncio.sleep(1)
        #await ps.stop()
        #return
        idx = 0
        async for output in ps.end_invoke(task):
            idx += 1
            print(f"{idx} - Received output: {output}")

        progress = await read

        idx = 0
        #async for output in ps.invoke(input_data=input_data):
        #    idx += 1
        #    print(f"{idx} - Received output: {output}")

        #await ps.stop()
        #res = await task
        
        for err in ps.streams['error']:
            print(f'Error: {err!s}')

        a = ''


async def main():
    await asyncio.gather(
        async_psrp(AsyncProcessInfo()),
        async_psrp(AsyncWSManInfo(f'http://{endpoint}:5985/wsman')),
    )


asyncio.run(main())


"""


def normal_test():
    with WSMan(endpoint) as wsman, WinRS(wsman) as shell:
        proc = Process(shell, 'cmd.exe', ['/c', 'echo hi'])
        proc.invoke()
        proc.signal(SignalCode.TERMINATE)
        print("STDOUT:\n%s\nSTDERR:\n%s\nRC: %s" % (proc.stdout.decode(), proc.stderr.decode(), proc.rc))

    with WSMan(endpoint) as wsman, RunspacePool(wsman) as rp:
        ps = PowerShell(rp)
        ps.add_script('echo "hi"')
        output = ps.invoke()
        print("\nPSRP: %s" % output)


async def async_test():
    #async with AsyncWSMan(endpoint) as wsman, AsyncWinRS(wsman) as shell:
    #    proc = AsyncProcess(shell, 'cmd.exe', ['/c', 'echo hi'])
    #    await proc.invoke()
    #    await proc.signal(SignalCode.TERMINATE)
    #    print("STDOUT:\n%s\nSTDERR:\n%s\nRC: %s" % (proc.stdout.decode(), proc.stderr.decode(), proc.rc))

    async with AsyncWSMan(endpoint) as wsman, AsyncRunspacePool(wsman) as rp:
        ps = AsyncPowerShell(rp)
        ps.add_script('echo "hi"')
        output = await ps.invoke()
        print("\nPSRP: %s" % output)


async def async_process():
    async with PowerShellProcess() as proc, AsyncRunspacePool(proc) as rp:
        ps = AsyncPowerShell(rp)
        ps.add_script('echo "hi"')
        output = await ps.invoke()
        print("\nPSRP: %s" % output)


async def async_h2():
    from psrp.winrs import (
        AsyncWinRS,
    )

    connection_uri = 'http://server2019.domain.test:5985/wsman'

    async with AsyncWinRS(connection_uri) as shell:
        proc = await shell.execute('powershell.exe', ['-Command', 'echo "hi"'])
        async with proc:
            data = await proc.stdout.read()
            await proc.wait()
            print(data)


async def async_psrp():
    from psrp.powershell import (
        AsyncRunspacePool,
    )
    rp = AsyncRunspacePool()
    rp.open()


#normal_test()
#print()

#asyncio.run(async_test())
#print()
#asyncio.run(async_process())

asyncio.run(async_psrp())
"""