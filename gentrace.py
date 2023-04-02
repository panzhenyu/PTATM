import argparse, subprocess, sys, re
from claripy import atexit

"""
Usage: sudo python3 gentrace.py [options] -- <command>
Generate probe trace for a command, make sure you have the root privilege.

    -p, --probe     probe to instrument(separate by ',' or provide multiple option), you should provide at least one probe.
    -c, --clock     clock the tracer used, default is global, see /sys/kernel/tracing/trace_clock.
    -r, --repeat    generate multiple trace information by repeating each input, default is 1.

[output format]
    [command] [clock]
        tsc,probe_event
        ...
    [command] [clock]
        ...
    ...
"""

# args.
COMMAND = "/home/pzy/project/PTATM/benchmark/benchmark"
PROBES = [
    "fib__0=fib",
    "fib=fib%return",
    "main__0=main",
    "main__1=main+0x66",
    "main=main%return",
    "indirectJump__0=indirectJump",
    "indirectJump=indirectJump%return",
    "foo__0=foo",
    "foo=foo%return",
    "indirectCall__0=indirectCall",
    "indirectCall=indirectCall%return",
    "directCall__0=directCall",
    "directCall=directCall%return"
]
CLOCK = "x86-tsc"
REPEAT = 2

# probe vars.
PGROUP = "ETCG"
PROBE_PREFIX = PGROUP + ':'
PROBE_ALL = PROBE_PREFIX + '*'

# trace vars.
TRACE_ROOT      = "/sys/kernel/tracing/"
TRACE_FILE      = TRACE_ROOT + "trace"
TRACE_ON        = TRACE_ROOT + "tracing_on"
TRACE_CLOCK     = TRACE_ROOT + "trace_clock"
EVENT_ROOT      = TRACE_ROOT + "events/"
GLOBAL_ENABLE   = EVENT_ROOT + "enable"
GROUP_ENABLE    = EVENT_ROOT + PGROUP + "/enable"

def exec(shellcmd: str) -> bool:
    return 0 == subprocess.run(shellcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode

def execWithResult(shellcmd: str):
    return subprocess.run(shellcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def addprobe(binary: str, probe: str) -> bool:
    return exec("perf probe -x " + binary + " -a " + probe)

def delprobe(probe: str) -> bool:
    return exec("perf probe -d " + probe)

def enableTrace() -> bool:
    return exec("echo 1 > " + GROUP_ENABLE) and exec("echo 1 > " + TRACE_ON)

def disableAllTrace() -> bool:
    return exec("echo 0 > " + GLOBAL_ENABLE)

def setTraceClock(clock: str) -> bool:
    return exec("echo " + clock + " > " + TRACE_CLOCK)

def getTraceClock() -> str|None:
    result = execWithResult("cat " + TRACE_CLOCK)
    if result.returncode != 0:
        catinfo = result.stdout.decode('utf-8')
        grp = re.search(r'\[(.*)\]', catinfo)
        return None if grp is None else grp[1]
    return None

def clearTrace() -> bool:
    return exec("echo > " + TRACE_FILE)

def fetchSegmentAndTime(traceinfo: str) -> str:
    pure = str()
    for trace in [record.strip() for record in traceinfo.strip().split('\n')]:
        info = trace.split(' ')
        time, segname = None, None
        for elem in info:
            timeres = re.match(r'^[1-9]\d*(\.\d+)?$', elem[:-1])
            segres = re.match(r'.+__.+', elem[:-1])
            if timeres != None:
                time = timeres.group()
            if segres != None:
                segname = segres.group()
        # TODO: Direct index is unsafe.
        pure += time + ',' + segname + '\n'
    return pure

# Returns (True, trace) or (False, error message).
def collectTrace(command: str) -> tuple:
    if not clearTrace():
        return (False, "Clear trace failed.\n")

    countline_result = execWithResult("expr 1 + `cat " + TRACE_FILE + " | wc -l`")
    if countline_result.returncode != 0:
        return (False, "Count lines for trace file failed.\n")
    skip = countline_result.stdout.decode().strip()

    if not exec(command):
        return (False, "Run command " + command + " failed.\n")
    traceinfo_result = execWithResult("cat " + TRACE_FILE + " | tail -n +" + skip)
    if traceinfo_result.returncode != 0:
        return (False, "Cat trace file failed.\n")

    return (True, fetchSegmentAndTime(traceinfo_result.stdout.decode('utf-8')))

if __name__ == "__main__":
    clock_old = getTraceClock()
    if clock_old is not None:
        atexit.register(setTraceClock, clock_old)
    atexit.register(delprobe, PROBE_ALL)
    atexit.register(disableAllTrace)

    # Add probes.
    delprobe(PROBE_ALL)
    binary = COMMAND.split(' ')[0]
    for probe in PROBES:
        if not addprobe(binary, PROBE_PREFIX + probe):
            sys.stderr.write("Failed to add probe " + probe + '.\n')
            exit(-1)

    # Start collect.
    if not setTraceClock(CLOCK):
        sys.stderr.write("Failed to set clock " + CLOCK + '.\n')
        exit(-2)
    if not disableAllTrace() or not enableTrace():
        sys.stderr.write("Failed to start trace.\n")
        exit(-3)
    for i in range(REPEAT):
        ok, msg = collectTrace(COMMAND)
        if not ok:
            sys.stderr.write("Failed to collect trace for command " + COMMAND + ".\n" + msg)
            exit(-4)
        else:
            sys.stdout.write("[%s] [%s]\n%s" % (COMMAND, CLOCK, msg))
