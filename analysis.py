from functools import reduce
import os, sys, math, json, datetime, random, signal, traceback, argparse, subprocess, multiprocessing

helper = """
Usage: python3 analysis.py command [options] ...
Provide pwcet analysis service.

[command]
    segment     parse binary file into segment.
        positional argument     required    path to binary file.
        -f, --function=         repeated    interested functions, default is main only.
        -s, --max-seg=          optional    max segment num, default is 2.
        -v, --verbose           optional    generate detail.
        -o, --output=           required    path to save segment result.

        [output]
            Append probes separate by ',' into output.

    control     generate shared resource controller of taskset.
        positional argument     required    path to file includes parallel tasks.
        -w, --llc-wcar=         optional    use llc wcar to generate resource controller.
        -F, --force             optional    force to measure wcar for each task.
        -v, --verbose           optional    generate detail.
        -o, --output=           required    path to save control task.

        [input]
            [positional argument]
                File is in json format.
                [
                    {
                        "core": core set used by task,
                        "dir": working directory,
                        "cmd": command,
                        "llc-wcar": llc-wcar
                    },
                    other task...
                ]
            [llc-wcar]
                An integer hints a cache access occurs every ${llc-wcar} instructions.

        [output]
            Executable file of control task.

        [note]
            We will save wcar result into the file provided by positional argument.

    collect     collect trace for task.
        positional argument     required    path to config of the target to collect and its contenders.
        -c, --clock=            optional    clock the tracer used, default is global, see man perf record.
        -r, --repeat=           optional    generate multiple trace information by repeating each input, default is 20.
        -v, --verbose           optional    generate detail.
        -o, --output=           required    path to save trace.

        [input]
            [positional argument]
                File is in json format.
                {
                    "target": {
                        "core": core set used by target,
                        "task": [
                            {
                                "dir": working directory,
                                "binary": path to binary file,
                                "probes": [uprobe1, uprobe2, ...],
                                "inputs": [arguments1, arguments2, ...]
                            },
                            other task to collect...
                        ]
                    },
                    "contender": {
                        "core": core set used by contender,
                        "task": [
                            {
                                "dir": working directory, 
                                "cmd": command1
                            },
                            other contender...
                        ]
                    }
                }

        [output]
            Append trace information into trace file, the trace format is:
            [${binary} ${args}]
            time1,uprobe1
            ...

    seginfo     dump trace/seginfo, and generate a new seginfo.
        positional argument     ignored
        -r, --raw-trace=        repeated    path to raw trace file.
        -j, --json-trace=       repeated    path to json trace file(segment info).
        -m, --strip-mode=       repeated    choose time or callinfo or both to strip.
        -v, --verbose           optional    generate detail.
        -o, --output=           required    path to save seginfo.

        [limit]
            num of trace-file sum num of seginfo must be grater than 0.
            if only one seginfo is provoided, the strip-mode must be selected.

        [input]
            [trace-file]
                File format see command collect.
            [seginfo]
                A file in json format, see SegmentInforCollector/TraceTool.py for detail.
            [strip-mode]
                You can choose time, callinfo.
                Strip time will clear all time information for seginfo file.
                Strip callinfo will make an unique callinfo list for seginfo file.

        [output]
            Segment information in json format, see SegmentInforCollector/TraceTool.py for detail.

    pwcet       generate pwcet result, build arguments of extreme distribution for segment and expression for function.
        positional argument     reuqired    path to segment information(or json trace).
        -f, --function=         repeated    target functions to generate, default is main only.
        -t, --evt-type=         optional    choose type of EVT family(GEV or GPD), default is GPD.
        -F, --force             optional    force to rebuild arguments of extreme distribution and expressions, even if they are already exist.
        -p, --prob=             repeated    exceedance probability, default is [1e-1, ..., 1e-9].
        -m, --mode=             optional    output mode, choose txt or png, default is txt.
        -v, --verbose           optional    generate detail.
        -o, --output=           required    path to save pwcet result.

        [input]
            [positional argument]
                File of segment information in json format, see SegmentInforCollector/TraceTool.py for detail.

        [output]
            When mode is txt, then we append pwcet estimate for each function into output, the format is:
            function,prob1,prob2,...
            func1,pWCET11,pWCET12,...
            func2,pWCET21,pWCET22,...
            pwcet estimate for other function...
            When mode is png, then we output a png file with pwcet curve for each function.
        
        [note]
            We will save arguments of extreme distribution and expressions into the file provided 
            by positional argument, see PWCETGenerator/PWCETSolver.py for detail.
"""

root = os.getenv('PTATM', 'None')

def exec(shellcmd: str) -> bool:
    return 0 == subprocess.run(shellcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode

def execWithResult(shellcmd: str):
    return subprocess.run(shellcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def execWithProcess(shellcmd: str):
    return subprocess.Popen(shellcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def issudo() -> bool:
    return os.getuid() == 0

def report(s: str):
    sys.stdout.write('[%s] %s\n' % (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), s))

def info(s: str):
    report('[INFO] %s' % s)

def warn(s: str):
    report('[WARN] %s' % s)

class SegmentModule:
    @staticmethod
    def genprobes(binary: str, functions: list, max_seg: int, verbose: bool):
        import angr
        from CFG2Segment import CFGBase, CFGRefactor, SFGBase, SFGBuilder

        # Parse binary with angr.
        if verbose:
            info('Build angr cfg for binary[%s].' % binary)
        angr_project = angr.Project(binary, load_options={'auto_load_libs': False})
        angr_cfg = angr_project.analyses.CFGFast()

        # Refactor CFG.
        if verbose:
            info('Refactor angr cfg.')
        cfg = CFGBase.CFG(angr_cfg)
        cfg_refactor = CFGRefactor.FunctionalCFGRefactor()
        refactor_result = cfg_refactor.refactor(cfg)

        # Build SFG.
        if verbose:
            info('Segment cfg with max_seg[%d] for function%s.' % (max_seg, functions))
        sfg = SFGBase.SFG(cfg)
        sfg_builder = SFGBuilder.FunctionalSFGBuilder(max_seg, functions)
        build_result = sfg_builder.build(sfg)

        # Dump uprobes.
        if verbose:
            info('Dump uprobes.')
        probes = []
        for name in functions:
            segfunc = sfg.getSegmentFunc(name)
            if segfunc is None:
                continue
            for segment in segfunc.segments:
                offset = hex(segment.startpoint.addr - segfunc.addr)
                probe_prefix = segment.name + "="
                probe_suffix = segfunc.name + ("+" + offset if offset != "0x0" else '')
                probes.append(probe_prefix + probe_suffix)
            probes.append(segfunc.name + "=" + segfunc.name + r"%return")
        return probes

    @staticmethod
    def service(args):
        if not hasattr(args, 'function'):
            args.function = ['main']
        probes = SegmentModule.genprobes(args.binary, args.function, args.max_seg, args.verbose)
        if args.verbose:
            info('Save result into %s' % args.output)
        with open(args.output, 'a') as output:
            output.write('\n' + reduce(lambda x, y: x + ',' + y, probes))

class ControlModule:
    # MACRO for gencarsim.
    NOP         = 'nop;'
    SIMSRC      = root + '/L3Contention/CARSimulator.c'
    SIMCMD      = 'gcc -DNOPSTR=\'"%s"\' -O1 -o %s %s'

    # MACRO for genwcar.
    RANDOMIZER  = root + '/L3Contention/RandomizeBuddy'
    PROFILER    = root + '/L3Contention/profiler'
    TMPFILE     = '/tmp/PTATM-wcar.json'
    TARGETID    = 'target'
    MODE        = 'SAMPLE_ALL'
    INS         = 'INSTRUCTIONS'
    LLC_ACC     = 'LLC_REFERENCES'
    CYCLE       = 'CYCLES'
    PERIOD      = 1000000000
    PERFCMD     = '%s --output=%s --log=/dev/null --json-plan=\'%s\' --cpu=%%d'
    REPEAT      = 1

    # MACRO for service.
    CORE        = 'core'
    DIR         = 'dir'
    CMD         = 'cmd'
    LLC_WCAR    = 'llc-wcar'

    @staticmethod
    def gencarsim(car, output):
        nopstr = ControlModule.NOP * max(0, car-6)
        cmd = ControlModule.SIMCMD % (nopstr, output, ControlModule.SIMSRC)
        return execWithResult(cmd)

    @staticmethod
    def genwcar(command, cpuset: list):
        target_plan = json.dumps({
            'id': ControlModule.TARGETID,
            'type': ControlModule.MODE,
            'task': command,
            'rt': True,
            'pincpu': True,
            'leader': ControlModule.CYCLE,
            'period': ControlModule.PERIOD,
            'member': [ControlModule.INS, ControlModule.LLC_ACC]
        })
        tmpfile = ControlModule.TMPFILE
        pcmd = ControlModule.PERFCMD % (ControlModule.PROFILER, tmpfile, target_plan)

        # Start collecting.
        if os.path.exists(tmpfile) and not exec('rm ' + tmpfile):
            raise Exception('Cannot remove temp file[%s].' % tmpfile)

        for _ in range(ControlModule.REPEAT):
            cpu = cpuset[random.randint(0, len(cpuset)-1)]
            exec(ControlModule.RANDOMIZER)
            if not exec(pcmd % cpu):
                raise Exception('Failed to exec [%s] on core[%d]' % (pcmd, cpu))

        # Gen worst car.
        wcar = None
        for data in json.loads(open(tmpfile, 'r').read()):
            target = data[ControlModule.TARGETID]
            inslist, acclist = target[ControlModule.INS], target[ControlModule.LLC_ACC]
            for i in range(min(len(inslist), len(acclist))):
                ins, acc = int(inslist[i]), int(acclist[i])
                if ins != 0 and acc != 0:
                    car = math.ceil(ins / acc)
                    wcar = car if wcar is None else min(wcar, car)
        return wcar

    @staticmethod
    def checkconf(conf: dict):
        for task in conf:
            for core in task[ControlModule.CORE]:
                if not isinstance(core, int) or core >= multiprocessing.cpu_count() or core < 0:
                    raise Exception("Invalid core[%d]." % core)
            if not isinstance(task[ControlModule.DIR], str):
                raise Exception("Invalid dir[%s]." % task[ControlModule.DIR])
            if not isinstance(task[ControlModule.CMD], str):
                raise Exception("Invalid cmd[%s]." % task[ControlModule.DIR])
            if not isinstance(task.get(ControlModule.LLC_WCAR, -1), int):
                raise Exception("Invalid llc-wcar[%s]." % task[ControlModule.LLC_WCAR])

    @staticmethod
    def service(args):
        llc_wcar = None

        if not issudo():
            raise Exception('You should run as a sudoer.')

        if os.path.exists(args.output):
            raise Exception('Output[%s] is already exist.' % args.output)

        if hasattr(args, 'llc_wcar'):
            llc_wcar = args.llc_wcar
        else:
            taskjson = json.loads(open(args.taskconf, 'r').read())
            ControlModule.checkconf(taskjson)
            try:
                for task in taskjson:
                    # Collect wcar for each task.
                    if args.force or int(task.get(ControlModule.LLC_WCAR, -1)) < 0:
                        # Get necessary fields from config.
                        core = task[ControlModule.CORE]
                        wdir = task[ControlModule.DIR]
                        cmd = task[ControlModule.CMD]
                        # Collect wcar for current task.
                        pwd = os.getcwd()
                        os.chdir(wdir)
                        task_wcar = ControlModule.genwcar(cmd, core)
                        os.chdir(pwd)
                        # Save wcar into json opbject.
                        task[ControlModule.LLC_WCAR] = task_wcar
                        if args.verbose:
                            info('Collect task[%s] done with wcar[%d].' % (cmd, task_wcar))
                    task_wcar = task[ControlModule.LLC_WCAR]
                    llc_wcar = task_wcar if llc_wcar is None else min(llc_wcar, task_wcar)
                # Save llc_wcar result into args.taskconf
                if args.verbose:
                    info('Save wcar result into taskconf[%s].' % (args.taskconf))
            except Exception as error:
                raise error
            finally:
                open(args.taskconf, 'w').write(json.dumps(taskjson, indent=4))

        # Generate car simulator with llc_wcar.
        if llc_wcar is not None:
            info('Generate control task at output[%s].' % args.output)
            result = ControlModule.gencarsim(llc_wcar, args.output)
            if 0 != result.returncode:
                raise Exception(result.stderr.decode('utf-8'))
        else:
            raise Exception('Invalid llc_wcar[None].')

class CollectModule:
    # MACRO for service.
    RANDOMIZER  = root + '/L3Contention/RandomizeBuddy'
    TARGET      = 'target'
    CONTENDER   = 'contender'
    CORE        = 'core'
    TASK        = 'task'
    DIR         = 'dir'
    BINARY      = 'binary'
    PROBES      = 'probes'
    INPUTS      = 'inputs'
    CMD         = 'cmd'

    @staticmethod
    def gentrace(binary: str, command: str, uprobes: list, clock: str):
        from SegmentInfoCollector.Collector import TraceCollector

        # Del all uprobes.
        TraceCollector.delprobe(TraceCollector.PROBE_ALL)
        try:
            # Add uprobes.
            for uprobe in uprobes:
                if not TraceCollector.addprobe(binary, TraceCollector.PROBE_PREFIX + uprobe):
                    raise Exception('Failed to add uprobe[%s] for binary[%s].' % (uprobe, binary))
            # Start collect.
            ok, info = TraceCollector.collectTrace(command, clock)
            if not ok:
                raise Exception('Failed to collect info for command[%s] with clock[%s].\n%s' % (command, clock, info))
        except Exception as error:
            raise error
        finally:
            # Clean all uprobes.
            TraceCollector.delprobe(TraceCollector.PROBE_ALL)
        return info

    @staticmethod
    def compete(contender: dict, core: int):
        os.setpgid(0, 0)
        def handler(x, y):
            os.killpg(os.getpgid(0), signal.SIGKILL)
        signal.signal(signal.SIGTERM, handler)

        contenders, nr_contender = contender[CollectModule.TASK], len(contender[CollectModule.TASK])
        gencmd = lambda task: 'cd %s && taskset -c %d %s' % (task[CollectModule.DIR], core, task[CollectModule.CMD])
        while True:
            contender_id = random.randint(0, nr_contender-1)
            proc = execWithProcess(gencmd(contenders[contender_id]))
            proc.wait()

    @staticmethod
    def checkconf(conf: dict):
        target = conf[CollectModule.TARGET]
        # Check target.
        for core in target[CollectModule.CORE]:
            if not isinstance(core, int) or core >= multiprocessing.cpu_count() or core < 0:
                raise Exception('Invalid core[%d].' % core)
        for task in target[CollectModule.TASK]:
            # Check dir.
            if not isinstance(task[CollectModule.DIR], str):
                raise Exception('Invalid dir[%s].' % task[CollectModule.DIR])
            # Check binary.
            if not isinstance(task[CollectModule.BINARY], str):
                raise Exception('Invalid binary[%s].' % task[CollectModule.BINARY])
            # Check probes.
            for uprobe in task[CollectModule.PROBES]:
                if not isinstance(uprobe, str):
                    raise Exception('Invalid uprobe[%s].' % uprobe)
            # Check inputs:
            for in_vec in task[CollectModule.INPUTS]:
                if not isinstance(in_vec, str):
                    raise Exception('Invalid input[%s].' % in_vec)

        # Check contender.
        contender = conf[CollectModule.CONTENDER]
        for core in contender[CollectModule.CORE]:
            if not isinstance(core, int) or core >= multiprocessing.cpu_count() or core < 0:
                raise Exception('Invalid core[%d].' % core)
        for task in contender[CollectModule.TASK]:
            # Check dir.
            if not isinstance(task[CollectModule.DIR], str):
                raise Exception('Invalid dir[%s].' % task[CollectModule.DIR])
            # Check cmd.
            if not isinstance(task[CollectModule.CMD], str):
                raise Exception('Invalid cmd[%s].' % task[CollectModule.CMD])

    @staticmethod
    def service(args):
        if not issudo():
            raise Exception('You should run as a sudoer.')

        taskjson = json.loads(open(args.taskconf, 'r').read())
        CollectModule.checkconf(taskjson)
        target, contender = taskjson[CollectModule.TARGET], taskjson[CollectModule.CONTENDER]

        # Start contender at each core.
        contender_procset = set()
        for core in contender[CollectModule.CORE]:
            if args.verbose:
                info('Start contender at core %d.' % core)
            contender_procset.add(multiprocessing.Process(target=CollectModule.compete, args=(contender, core)))
        for proc in contender_procset:
            proc.start()
        try:
            # Collect tarce for each target.
            target_coreset = target[CollectModule.CORE]
            outfile = open(args.output, 'a')
            pwd = os.getcwd()
            for task in target[CollectModule.TASK]:
                taskdir = task[CollectModule.DIR]
                binary = task[CollectModule.BINARY]
                uprobes = task[CollectModule.PROBES]
                inputs = task[CollectModule.INPUTS]
                cmdpat = 'taskset -c %%d %s %%s' % binary
                # Change working directory for collect.
                os.chdir(taskdir)
                for r in range(args.repeat):
                    for in_vec in inputs:
                        core = target_coreset[random.randint(0, len(target_coreset)-1)]
                        command = cmdpat % (core, in_vec)
                        if args.verbose:
                            info('Collect for command[%s] at %d time.' % (command, r+1))
                        # Randomize buddy.
                        exec(ControlModule.RANDOMIZER)
                        traceinfo = CollectModule.gentrace(binary, command, uprobes, args.clock)
                        outfile.write('\n[%s] [%s]\n' % (command, args.clock) + traceinfo)
                        outfile.flush()
        except Exception as error:
            raise error
        finally:
            os.chdir(pwd)
            # Terminate all alive contender.
            for proc in contender_procset:
                if proc.is_alive():
                    proc.terminate()
            # Close output.
            outfile.close()

class SeginfoModule:
    # MACRO for service.
    MODE = { 'time': None, 'callinfo': None }
    @staticmethod
    def service(args):
        from SegmentInfoCollector import TraceTool
        # Check whether output is exist.
        if os.path.exists(args.output):
            raise Exception('Output[%s] is already exist.' % args.output)

        # Check whether there is something to do with trace.
        nr_trace = len(args.raw_trace) + len(args.json_trace)
        if nr_trace == 0:
            warn('Nothing to dump.')
            return
        elif nr_trace == 1 and len(args.json_trace) == 1 and not hasattr(args, 'strip_mode'):
            warn('Nothing to dump for single json trace without strip mode selected.')
            return

        # Build trace object(seginfo).
        traceobj = TraceTool.Trace()
        # Fill raw trace.
        rawfiller = TraceTool.RawTraceStringFiller(traceobj)
        jsonfiller = TraceTool.JsonTraceFiller(traceobj)
        for rtrace in args.raw_trace:
            if args.verbose:
                info('Build raw trace[%s].' % rtrace)
            if rawfiller.fill(open(rtrace, 'r').read()) == False:
                raise Exception("Build raw trace[%s] failed with err_msg[%s]." % (rtrace, rawfiller.err_msg))
        # Fill json trace.
        for jtrace in args.json_trace:
            if args.verbose:
                info('Build json trace[%s].' % jtrace)
            if jsonfiller.fill(open(jtrace, 'r').read()) == False:
                raise Exception("Build json trace[%s] failed with err_msg[%s]." % (jtrace, jsonfiller.err_msg))
        # Strip trace object(seginfo).
        if hasattr(args, 'strip_mode'):
            for mode in args.strip_mode:
                stripper = None
                if mode == 'time':
                    stripper = TraceTool.CostTimeStripper(traceobj)
                elif mode == 'callinfo':
                    stripper = TraceTool.CallinfoStripper(traceobj)
                if args.verbose:
                    info('Strip seginfo with mode[%s].' % mode)
                if stripper is not None and stripper.strip() == False:
                    raise Exception("Strip trace failed at mode[%s] with err_msg[%s]." % (mode, stripper.err_msg))
        # Output trace object(seginfo).
        if args.verbose:
            info('Output seginfo into %s.' % args.output)
        with open(args.output, 'w') as outfile:
            outfile.write(TraceTool.JsonTraceSerializer(4).serialize(traceobj))

class PWCETModule:
    # MACRO for service.
    EVT = { 'GEV': None, 'GPD': None }
    MODE = { 'txt': None, 'png': None }

    @staticmethod
    def service(args):
        from SegmentInfoCollector import TraceTool
        from PWCETGenerator import EVTTool, PWCETSolver

        # Set default value for function & prob.
        if not hasattr(args, 'function'):
            args.function = ['main']
        if not hasattr(args, 'prob'):
            args.prob = [10**-x for x in range(1, 10)]

        # Check default value for evt_type & mode.
        if args.evt_type not in PWCETModule.EVT:
            raise Exception('Unrecognized evt-type[%s].' % args.evt_type)
        if args.mode not in PWCETModule.MODE:
            raise Exception('Unrecognized mode[%s].' % args.mode)
        
        # Check whether output is exist.
        if args.mode != 'txt' and os.path.exists(args.output):
            raise Exception('Output[%s] is already exist.' % args.output)

        # Create trace object.
        if args.verbose:
            info('Build trace object(seginfo) for %s.' % args.seginfo)
        traceobj = TraceTool.Trace()
        TraceTool.JsonTraceFiller(traceobj).fill(open(args.seginfo, 'r').read())

        # Initialize solver with evt_type.
        if args.verbose:
            info('Generate solver with evt-type[%s].' % args.evt_type)
        if args.evt_type == 'GEV':
            solver = PWCETSolver.GumbelSegmentListSolver()
        elif args.evt_type == 'GPD':
            solver = PWCETSolver.ExponentialParetoSegmentListSolver()
        
        # Solve trace object.
        if args.verbose:
            info('Solve with force=%s.' % str(args.force))
        if not solver.solve(traceobj, args.force):
            raise Exception('Failed to solve seginfo[%s].\n[%s]' % (args.seginfo, solver.err_msg))
        
        # Save solve result.
        if args.verbose:
            info('Save solve result into %s.' % args.seginfo)
        with open(args.seginfo, 'w') as seginfo:
            seginfo.write(TraceTool.JsonTraceSerializer(4).serialize(traceobj))

        # Get distribution for each function.
        distribution = dict()
        for fname in args.function:
            if args.verbose:
                info('Generate distribution for function[%s].' % fname)
            lextd = solver.lextd4Function(fname)
            if lextd == None:
                raise Exception('Failed to generate distribution for function[%s], try to use -F.' % fname)
            distribution[fname] = lextd

        # Generate result.
        if args.verbose:
            info('Generate result into %s with mode[%s].' % (args.output, args.mode))
        if args.mode == 'txt':
            with open(args.output, 'a') as output:
                # Write head line.
                headline = reduce(lambda x, y: str(x)+','+str(y), ['function'] + args.prob)
                output.write('\n' + headline)
                # Write pwcet estimate for each function.
                for fname in args.function:
                    pwcet = [round(distribution[fname].isf(p), 4) for p in args.prob]
                    body = reduce(lambda x, y: str(x)+','+str(y), [fname] + pwcet)
                    output.write('\n' + body)
        elif args.mode == 'png':
            pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='pwcet analysis service.')

    # Set subcommand parser.
    subparsers = parser.add_subparsers(title='command')

    # Add subcommand segment.
    segment = subparsers.add_parser('segment', help='parse binary file into segment')
    segment.add_argument('binary', 
                         help='path to binary file')
    segment.add_argument('-f', '--function', metavar='', action='extend', default=argparse.SUPPRESS, nargs='+', 
                         help='function name, default is main only')
    segment.add_argument('-s', '--max-seg', metavar='', type=int, default=2, 
                         help='max segment num, default is 2')
    segment.add_argument('-v', '--verbose', action='store_true', 
                         help='generate detail')
    segment.add_argument('-o', '--output', metavar='', required=True, 
                         help='path to save segment result')
    segment.set_defaults(func=SegmentModule.service)

    # Add subcommand control.
    control = subparsers.add_parser('control', help='generate shared resource controller of taskset')
    control.add_argument('taskconf', 
                         help="path to file who includes parallel tasks")
    control.add_argument('-w', '--llc-wcar', metavar='', type=int, default=argparse.SUPPRESS,
                         help='use llc wcar to generate resource controller')
    control.add_argument('-F', '--force', action='store_true', 
                         help='force to measure wcar for each task')
    control.add_argument('-v', '--verbose', action='store_true', 
                         help='generate detail')
    control.add_argument('-o', '--output', metavar='', required=True, 
                         help='path to save control task')
    control.set_defaults(func=ControlModule.service)

    # Add subcommand collect.
    collect = subparsers.add_parser('collect', help='collect trace for task')
    collect.add_argument('taskconf', 
                         help="path to config of the target to collect and its contenders")
    collect.add_argument('-c', '--clock', metavar='', default='global', 
                         help='clock the tracer used, default is global, see man perf record')
    collect.add_argument('-r', '--repeat', metavar='', type=int, default=20, 
                         help='generate multiple trace information by repeating each input, default is 20')
    collect.add_argument('-v', '--verbose', action='store_true', 
                         help='generate detail')
    collect.add_argument('-o', '--output', metavar='', required=True, 
                         help='path to save trace')
    collect.set_defaults(func=CollectModule.service)

    # Add subcommand seginfo.
    seginfo = subparsers.add_parser('seginfo', help='dump trace/seginfo, and generate a new seginfo')
    seginfo.add_argument('-r', '--raw-trace', metavar='', action='extend', default=list(), nargs='+', 
                         help='path to raw trace file')
    seginfo.add_argument('-j', '--json-trace', metavar='', action='extend', default=list(), nargs='+', 
                         help='path to json trace file(segment info)')
    seginfo.add_argument('-m', '--strip-mode', action='extend', choices=list(SeginfoModule.MODE.keys()), 
                         default=argparse.SUPPRESS, nargs='+', 
                         help='choose time or callinfo or both to strip')
    seginfo.add_argument('-v', '--verbose', action='store_true', 
                         help='generate detail')
    seginfo.add_argument('-o', '--output', metavar='', required=True, 
                         help='path to save seginfo')
    seginfo.set_defaults(func=SeginfoModule.service)

    # Add subcommand pwcet.
    pwcet = subparsers.add_parser('pwcet', help='generate pwcet result, build arguments of extreme distribution for segment and expression for function')
    pwcet.add_argument('seginfo', 
                         help='path to segment information(or json trace)')
    pwcet.add_argument('-f', '--function', metavar='', action='extend', default=argparse.SUPPRESS, nargs='+', 
                         help='target functions to generate, default is main only')
    pwcet.add_argument('-t', '--evt-type', choices=list(PWCETModule.EVT.keys()), default='GPD', 
                         help='choose type of EVT family(GEV or GPD), default is GPD')
    pwcet.add_argument('-F', '--force', action='store_true', 
                         help='force to rebuild arguments of extreme distribution and expressions, even if they are already exist')
    pwcet.add_argument('-p', '--prob', metavar='', type=float, action='extend', default=argparse.SUPPRESS, nargs='+', 
                         help='exceedance probability, default is [1e-1, ..., 1e-9]')
    pwcet.add_argument('-m', '--mode', choices=list(PWCETModule.MODE.keys()), default='txt', 
                         help='output mode, choose txt or png, default is txt')
    pwcet.add_argument('-v', '--verbose', action='store_true', 
                         help='generate detail')
    pwcet.add_argument('-o', '--output', metavar='', required=True, 
                         help='path to save pwcet result')
    pwcet.set_defaults(func=PWCETModule.service)

    try:
        # Check env.
        if os.getenv('PTATM') is None:
            raise Exception("Set PTATM env with shrc at first.")
        # Parse arguments.
        args = parser.parse_args()
        # Process subcommands.
        if not hasattr(args, 'func'):
            parser.print_help()
        else:
            args.func(args)
    except Exception as error:
        print(traceback.print_exc())
