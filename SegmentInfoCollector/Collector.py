import subprocess

class TraceCollector:
    # probe vars.
    PGROUP          = "ETCG"
    PROBE_PREFIX    = PGROUP + ':'
    PROBE_ALL       = PROBE_PREFIX + '*'
    RECORD_FILE     = "/tmp/PTATM-ETCG-record"

    @staticmethod
    def exec(shellcmd: str) -> bool:
        result = subprocess.run(shellcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return 0 == result.returncode

    @staticmethod
    def execWithResult(shellcmd: str):
        return subprocess.run(shellcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    @staticmethod
    def addprobe(binary: str, probe: str) -> bool:
        return TraceCollector.exec("perf probe -x " + binary + " -a " + probe)

    @staticmethod
    def delprobe(probe: str) -> bool:
        return TraceCollector.exec("perf probe -d " + probe)

    @staticmethod
    def fetchSegmentAndTime(traceinfo: str) -> str:
        pure = str()
        for trace in [record.strip() for record in traceinfo.strip().split('\n')]:
            info = trace.strip().split(' ')
            time = info[0][:-1]
            segname = info[-1][5:-1]
            pure += time + ',' + segname + '\n'
        return pure

    # Returns (True, trace) or (False, error message).
    @staticmethod
    def collectTrace(command: str, clock: str) -> tuple:
        record = "perf record -e %s -aR -k %s -o %s %s" % (TraceCollector.PROBE_ALL, clock, TraceCollector.RECORD_FILE, command)
        script = "perf script -F time,event -i %s" % TraceCollector.RECORD_FILE

        # Use perf record to collect trace.
        if not TraceCollector.exec(record):
            return (False, "Record command " + command + " failed.\n")

        # Use perf script to dump trace.
        traceinfo_result = TraceCollector.execWithResult(script)
        if traceinfo_result.returncode != 0:
            return (False, "Cat trace file failed.\n")
        
        # Fetch trace info from perf script result.
        return (True, TraceCollector.fetchSegmentAndTime(traceinfo_result.stdout.decode('utf-8')))
