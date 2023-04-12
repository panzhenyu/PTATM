import subprocess, re

class TraceCollector:
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
        return exec("echo 1 > " + TraceCollector.GROUP_ENABLE) and exec("echo 1 > " + TraceCollector.TRACE_ON)

    def disableAllTrace() -> bool:
        return exec("echo 0 > " + TraceCollector.GLOBAL_ENABLE)

    def setTraceClock(clock: str) -> bool:
        return exec("echo " + clock + " > " + TraceCollector.TRACE_CLOCK)

    def getTraceClock() -> str|None:
        result = TraceCollector.execWithResult("cat " + TraceCollector.TRACE_CLOCK)
        if result.returncode != 0:
            catinfo = result.stdout.decode('utf-8')
            grp = re.search(r'\[(.*)\]', catinfo)
            return None if grp is None else grp[1]
        return None

    def clearTrace() -> bool:
        return exec("echo > " + TraceCollector.TRACE_FILE)

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
        if not TraceCollector.clearTrace():
            return (False, "Clear trace failed.\n")

        countline_result = TraceCollector.execWithResult("expr 1 + `cat " + TraceCollector.TRACE_FILE + " | wc -l`")
        if countline_result.returncode != 0:
            return (False, "Count lines for trace file failed.\n")
        skip = countline_result.stdout.decode().strip()

        if not exec(command):
            return (False, "Run command " + command + " failed.\n")
        traceinfo_result = TraceCollector.execWithResult("cat " + TraceCollector.TRACE_FILE + " | tail -n +" + skip)
        if traceinfo_result.returncode != 0:
            return (False, "Cat trace file failed.\n")

        return (True, TraceCollector.fetchSegmentAndTime(traceinfo_result.stdout.decode('utf-8')))
