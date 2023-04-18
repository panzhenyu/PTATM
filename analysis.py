from functools import reduce
import os, sys, math, json, random, signal, traceback, argparse, subprocess, multiprocessing

helper = """
Usage: python3 analysis.py command [options] ...
Provide pwcet analysis service.

[command]
    segment     parse binary file into segment.
        positional argument     required    path to binary file.
        -f, --function=         repeated    interested functions, default is main only.
        -s, --max-seg=          optional    max segment num, default is 2.

        [output]
            stdout: probes separate by ','.

    control     generate shared resource controller of taskset.
        positional argument     required    path to file includes parallel tasks.
        -w, --llc-wcar=         optional    use llc wcar to generate resource controller.
        -F, --force             optional    force to measure wcar for each task.
        -v, --verbose           optional    generate detail.
        -o, --output=           required    path to save control task file.
        

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
            stdout: none.

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
            trace: trace information in text format.
            [${binary} ${args}]
            time1,uprobe1
            ...

    seginfo     dump trace/seginfo, and generate a new seginfo.
        positional argument     ignored
        -t, --trace-file=       repeated    path to trace file.
        -s, --seginfo=          repeated    path to segment info.
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
            seginfo: segment information in json format, see SegmentInforCollector/TraceTool.py for detail.

    pwcet       generate pwcet result, build arguments of extreme distribution for segment and expression for function.
        positional argument     reuqired    path to segment info.
        -f, --function=         repeated    target functions to generate, default is main only.
        -t, --evt-type=         optional    choose type of EVT family(GEV or GPD), default is GPD.
        -F, --force             optional    force to rebuild arguments of extreme distribution and expressions, even if they are already exist.
        -p, --prob=             repeated    exceedance probability, default is 1e-6.
        -v, --verbose           optional    generate pwcet curve of each function.
        -o, --output=           optional    path to output directory to save modified segment info and intermediate result, default is current dir.

        [input]
            [positional argument]
                File of segment information in json format, see SegmentInforCollector/TraceTool.py for detail.

        [verbose]
            ${func}-pwcet.png: pwcet curve for ${func}.

        [output]
            stdout: pwcet under exceedance probability(prob), format:
            function,prob1,prob2,...
            func1,pWCET11,pWCET12,...
            func2,pWCET21,pWCET22,...
            ...
        
        [note]
            We will save arguments of extreme distribution and expressions into the file provided 
            by positional argument, see PWCETGenerator/PWCETSolver.py for detail.
"""

root = os.getenv('PTATM', 'None')
childproc = set()

def exec(shellcmd: str) -> bool:
    return 0 == subprocess.run(shellcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode

def execWithResult(shellcmd: str):
    return subprocess.run(shellcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def execWithProcess(shellcmd: str):
    return subprocess.Popen(shellcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def issudo() -> bool:
    return os.getuid() == 0

def info(s: str):
    sys.stdout.write('[INFO] ' + s + '\n')

def warn(s: str):
    sys.stdout.write('[WARN] ' + s + '\n')

class SegmentModule:
    @staticmethod
    def genprobes(binary: str, functions: list, max_seg: int):
        import angr
        from CFG2Segment import CFGBase, CFGRefactor, SFGBase, SFGBuilder

        # Parse binary with angr.
        angr_project = angr.Project(binary, load_options={'auto_load_libs': False})
        angr_cfg = angr_project.analyses.CFGFast()

        # Refactor CFG.
        cfg = CFGBase.CFG(angr_cfg)
        cfg_refactor = CFGRefactor.FunctionalCFGRefactor()
        refactor_result = cfg_refactor.refactor(cfg)

        # Build SFG.
        sfg = SFGBase.SFG(cfg)
        sfg_builder = SFGBuilder.FunctionalSFGBuilder(max_seg, functions)
        build_result = sfg_builder.build(sfg)

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

        # Output refactor result and build result to stderr?
        return probes

    @staticmethod
    def service(args):
        if not hasattr(args, 'function'):
            args.function = ['main']
        probes = SegmentModule.genprobes(args.binary, args.function, args.max_seg)
        sys.stdout.write(reduce(lambda x, y: x + ',' + y, probes))

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
            exec(pcmd % cpu)

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
    def service(args):
        llc_wcar = None

        if not issudo():
            raise Exception('You should run as a sudoer.')
        
        if os.path.exists(args.output):
            raise Exception('Output[%s] is already exist.' % args.output)

        if hasattr(args, 'llc_wcar'):
            llc_wcar = int(args.llc_wcar)
        else:
            taskjson = json.loads(open(args.taskconf, 'r').read())
            for task in taskjson:
                # Collect wcar for each task.
                if args.force or ControlModule.LLC_WCAR not in task or int(task[ControlModule.LLC_WCAR]) < 0:
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
    TARGET      = 'target'
    CONTENDER   = 'contender'
    CORE        = 'core'
    TASK        = 'task'
    DIR         = 'dir'
    BINARY      = 'binary'
    PROBES      = 'probes'
    INPUTS      = 'inputs'
    CMD         = 'cmd'

    def gentrace(binary: str, command: str, uprobes: list, clock: str):
        from SegmentInfoCollector.Collector import TraceCollector

        # Del all uprobes.
        if not TraceCollector.delprobe(TraceCollector.PROBE_ALL):
            raise Exception('Cannot del all uprobe[%s].' % TraceCollector.PROBE_ALL)
            
        # Add uprobes.
        for uprobe in uprobes:
            if not TraceCollector.addprobe(binary, TraceCollector.PROBE_PREFIX + uprobe):
                raise Exception('Failed to add uprobe[%s].' % uprobe)

        # Start collect.
        result = TraceCollector.collectTrace(command)

        # Clean all uprobes.
        TraceCollector.delprobe(TraceCollector.PROBE_ALL)

        return result

    @staticmethod
    def compete(contender: dict, core):
        contenders, nr_contender = contender[CollectModule.TASK], len(contender[CollectModule.TASK])
        gencmd = lambda task: 'cd %s && taskset -c %d %s' % (task[CollectModule.DIR], core, task[CollectModule.CMD])
        while True:
            contender_id = random.randint(0, nr_contender-1)
            exec(gencmd(contenders[contender_id]))

    @staticmethod
    def service(args):
        """
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
        """
        if not issudo():
            raise Exception('You should run as a sudoer.')
        
        if os.path.exists(args.output):
            raise Exception('Output[%s] is already exist.' % args.output)
        
        taskjson = json.loads(open(args.taskconf, 'r').read())
        target, contender = taskjson[CollectModule.TARGET], taskjson[CollectModule.CONTENDER]
        
        # Start contender at each core.
        contender_coreset = contender[CollectModule.CORE]
        contender_procset = set()
        for core in contender_coreset:
            if args.verbose:
                info('Start contender at core %d.' % core)
            contender_procset.add(multiprocessing.Process(target=CollectModule.compete, args=(contender, core)))
        childproc.update(contender_procset)
        for proc in contender_procset:
            proc.start()

        # Collect tarce for each target.
        # target_coreset = target[CollectModule.CORE]
        # outfile = open(args.output, 'w')
        # for task in target[CollectModule.TASK]:
        #     taskdir = task[CollectModule.DIR]
        #     binary = task[CollectModule.BINARY]
        #     uprobes = task[CollectModule.PROBES]
        #     inputs = task[CollectModule.INPUTS]
        #     for _ in range(args.repeat):
        #         traceinfo = CollectModule.gentrace(binary, command, uprobes, args.clock)
        #         outfile.write(traceinfo + '\n')
        #         outfile.flush()
        # outfile.close()

        # Terminate all contender.
        for proc in contender_procset:
            proc.terminate()
            childproc.remove(proc)

class SeginfoModule:
    
    @staticmethod
    def service(args):
        pass

class PWCETModule:

    @staticmethod
    def service(args):
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
                         help='path to save control task file')
    control.set_defaults(func=ControlModule.service)

    # Add subcommand collect.
    collect = subparsers.add_parser('collect', help='collect trace for task')
    collect.add_argument('taskconf', 
                         help="path to config of the target to collect and its contenders")
    collect.add_argument('-c', '--clock', metavar='', default='global', 
                         help='clock the tracer used, default is global, see man perf record')
    collect.add_argument('-r', '--repeat', metavar='', type=int, default=100, 
                         help='generate multiple trace information by repeating each input, default is 20')
    collect.add_argument('-v', '--verbose', action='store_true', 
                         help='generate detail')
    collect.add_argument('-o', '--output', metavar='', required=True, 
                         help='path to save trace')
    collect.set_defaults(func=CollectModule.service)

    # Add subcommand seginfo.
    """
    seginfo     dump trace/seginfo, and generate a new seginfo.
    positional argument     ignored
    -t, --trace-file=       repeated    path to trace file.
    -s, --seginfo=          repeated    path to segment info.
    -m, --strip-mode=       repeated    choose time or callinfo or both to strip.
    """
    seginfo = subparsers.add_parser('seginfo', help='dump trace/seginfo, and generate a new seginfo')
    seginfo.set_defaults(func=SeginfoModule.service)

    # Add subcommand pwcet.
    """
    pwcet       generate pwcet result, build arguments of extreme distribution for segment and expression for function.
    positional argument     reuqired    path to segment info.
    -f, --function=         repeated    target functions to generate, default is main only.
    -t, --evt-type=         optional    choose type of EVT family(GEV or GPD), default is GPD.
    -F, --force             optional    force to rebuild arguments of extreme distribution and expressions, even if they are already exist.
    -p, --prob=             repeated    exceedance probability, default is 1e-6.
    -v, --verbose           optional    generate pwcet curve of each function.
    -o, --output=           optional    path to output directory to save modified segment info and intermediate result, default is current dir.
    """
    pwcet = subparsers.add_parser('pwcet', help='generate pwcet result, build arguments of extreme distribution for segment and expression for function')
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
        for proc in childproc:
            if proc.is_alive():
                proc.terminate()
        print(traceback.print_exc())
