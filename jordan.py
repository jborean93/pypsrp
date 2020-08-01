import logging
import pypsrp
import sys

log = logging.getLogger('')

log.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s')
handler.setFormatter(formatter)
log.addHandler(handler)


#with pypsrp.PowerShellProcess() as ps_proc, pypsrp.RunspacePool(ps_proc) as runspace:
with pypsrp.WSMan('server2019.domain.local', ssl=False) as wsman, pypsrp.RunspacePool(wsman) as runspace:
    ps = pypsrp.PowerShell(runspace)
    ps.add_script('$PSVersionTable')
    output = ps.invoke()
    ps.stop()


print(output)