class TraceCollector:
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
