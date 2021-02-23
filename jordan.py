import asyncio
import typing

from psrp import (
    AsyncRunspacePool,
    AsyncPowerShell,
    RunspacePool,
    PowerShell,

    AsyncProcessInfo,
    AsyncWSManInfo,
    ProcessInfo,
    WSManInfo,
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

from psrp.protocol.powershell import (
    Command,
    PipelineResultTypes,
)


endpoint = 'server2019.domain.test'

script = '''
'1'
#sleep 10
'2'
'''


async def async_psrp(connection_info):
    async with AsyncRunspacePool(connection_info) as rp:
        await rp.reset_runspace_state()
        await rp.set_max_runspaces(10)
        await rp.get_available_runspaces()

        #await asyncio.sleep(10)

        async def run_command(time_sec):
            ps = AsyncPowerShell(rp)
            ps.add_script(f'echo "hi"; sleep {time_sec}; echo "end"')
            print(await ps.invoke())

        #done, pending = await asyncio.wait([run_command(1), run_command(2), run_command(3)])
        #for d in done:
        #    print(d.result())



        ps = AsyncPowerShell(rp)
        ps.add_script('echo "hi"; echo 2; echo "test"')
        print(await ps.invoke())

    print("exit")
    return


async def async_reconnection(connection_info):
    async with AsyncRunspacePool(connection_info) as rp1:
        print(rp1.pool.runspace_id)
        #await rp1.disconnect()
        #await rp1.connect()

        ps = AsyncPowerShell(rp1)
        ps.add_script(script)
        task = await ps.invoke_async()
        #async for out in ps.invoke():
        #    print(out)

        await rp1.disconnect()

    a = ''

    #async with AsyncRunspacePool(AsyncWSManInfo(f'http://{endpoint}:5985/wsman')) as rp2:
    #    print(rp2.protocol.runspace_id)
    #    await rp2.disconnect()

    a = ''

    async for rp in AsyncRunspacePool.get_runspace_pools(connection_info):
        async with rp:
            a = ''
            for pipeline in rp.create_disconnected_power_shells():
                print(await pipeline.connect())

                a = ''
            a = ''


async def a_main():
    await asyncio.gather(
        #async_psrp(AsyncProcessInfo()),
        async_psrp(AsyncWSManInfo(f'http://{endpoint}:5985/wsman', verify=False)),
        #async_reconnection(AsyncWSManInfo(f'http://{endpoint}:5985/wsman')),
    )


def main():
    with RunspacePool(ProcessInfo()) as rp:
        rp.reset_runspace_state()
        rp.set_max_runspaces(10)
        rp.get_available_runspaces()
        print(rp.get_available_runspaces())

        p = PowerShell(rp)
        p.add_script('echo "hi"')
        print(p.invoke())


asyncio.run(a_main())
#main()


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
