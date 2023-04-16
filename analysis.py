from functools import reduce
import os, sys, json, random, traceback, argparse, subprocess

helper = """
Usage: python3 analysis.py command [options] ...
Provide pwcet analysis service.

[command]
    segment     parse binary file into segment.
        positional argument     required    path to binary file.
        -f, --function=         repeated    interested functions(separated by ',' or provide multiple option), default is main only.
        -s, --max-seg=          optional    max segment num, default is 2.

        [output]
            stdout: probes separate by ','.
    
    control     generate shared resource controller of taskset.
        positional argument     required    path to file includes parallel tasks.
        -w, --llc-wcar=         optional    use llc wcar to generate resource controller.
        -F, --force             optional    force to measure wcar for each task.
        -o, --output=           optional    path to save control task file, defualt is ./shared_controller

        [input]
            [positional argument]
                File is in json format.
                [
                    {
                        "core": core set used by task,
                        "command": command,
                        "llc-wcar": llc-wcar
                    },
                    other task...
                ]
            [llc-wcar]
                An integer hints a cache set access occurs every ${llc-wcar} instructions.

        [output]
            stdout: none.

        [note]
            We will save wcar result into the file provided by positional argument.

    collect     collect trace for task.
        positional argument     required    path to config of the target to collect and its contenders.
        -c, --clock=            optional    clock the tracer used, default is global, see /sys/kernel/tracing/trace_clock.
        -r, --repeat=           optional    generate multiple trace information by repeating each input, default is 20.
        
        [input]
            [positional argument]
                File is in json format.
                {
                    "target": {
                        "core": core set used by target,
                        "task": [
                            {
                                "binary": path to binary file,
                                "probes": [uprobe1, uprobe2, ...],
                                "inputs": [arguments1, arguments2, ...]
                            },
                            other task to collect...
                        ]
                    },
                    "contender": {
                        "core": core set used by contender,
                        "task": [command1, command2, ...]
                    }
                }

        [output]
            stdout: trace info, trace format:
            [${binary} ${args}]
            time1,uprobe1
            ...

    seginfo     dump trace/seginfo, and generate a new seginfo.
        positional argument     ignored
        -t, --trace-file=       repeated    path to trace file(separated by ',' or provide multiple option).
        -s, --seginfo=          repeated    path to segment info(separated by ',' or provide multiple option).
        -m, --strip-mode=       repeated    choose time or callinfo or both to strip(separated by ',' or provide multiple option).

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
            stdout: segment information in json format, see SegmentInforCollector/TraceTool.py for detail.

    pwcet       generate pwcet result, build arguments of extreme distribution for segment and expression for function.
        positional argument     reuqired    path to segment info.
        -f, --function=         repeated    target functions(separated by ',' or provide multiple option) to generate, default is main only.
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

root = os.getenv('PTATM')

def exec(shellcmd: str) -> bool:
    return 0 == subprocess.run(shellcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode

def execWithResult(shellcmd: str):
    return subprocess.run(shellcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def issudo() -> bool:
    return os.getuid() == 0

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
    @staticmethod
    def gencarsim(car, output):
        nopstr = 'nop;' * max(0, car-6)
        simsrc = root + '/L3Contention/CARSimulator.c'
        cmd = 'gcc -DNOPSTR=\'"%s"\' -O1 -o %s %s' % (nopstr, output, simsrc)
        return execWithResult(cmd)

    @staticmethod
    def genwcar(command, cpuset: list):
        randomizer = root + '/L3Contention/RandomizeBuddy'
        profiler = root + '/L3Contention/profiler'

        tmpfile = '/tmp/PTATM-wcar.json'
        target_plan = json.dumps({
            'id': 'target',
            'type': 'SAMPLE_ALL',
            'task': command,
            'rt': True, 
            'pincpu': True,
            'leader': 'CYCLES',
            'period': 50000000,
            'member': ['INSTRUCTIONS', 'LLC_REFERENCES']
        })
        perfcmd = 'sudo %s --output=%s --json-plan=\'%s\' --cpu=%%d' % (profiler, tmpfile, target_plan)

        # Start collecting.
        exec('rm ' + tmpfile)
        for _ in range(15):
            cpu = cpuset[random.randint(0, len(cpuset)-1)]
            exec(randomizer)
            result = execWithResult(perfcmd % cpu)

        # Gen worst car.
        wcar = -1
        for data in json.loads(open(tmpfile, 'r').read()):
            target = data['target']
            ins, acc = int(target['INSTRUCTIONS']), int(target['LLC_REFERENCES'])
            wcar = max(wcar, ins//acc)
        return wcar

    @staticmethod
    def service(args):
        if not issudo():
            raise Exception("you should run as a sudoer.")
        if hasattr(args, 'llc_wcar'):
            llc_wcar = int(args.llc_wcar)
        else:
            CORE = 'core'
            COMMAND = 'command'
            LLC_WCAR = 'llc-wcar'
            llc_wcar = -1

            taskjson = json.loads(open(args.taskconf, 'r').read())
            for task in taskjson:
                if COMMAND not in task:
                    continue
                if args.force or LLC_WCAR not in task or int(task[LLC_WCAR]) < 0:
                    coreset = [1] if CORE not in task else task[CORE]
                    task_wcar = ControlModule.genwcar(task[COMMAND], coreset)
                    task[LLC_WCAR] = int(task_wcar)
                llc_wcar = max(llc_wcar, task[LLC_WCAR])
            # Save llc_wcar result into args.taskconf
            open(args.taskconf, 'w').write(json.dumps(taskjson, indent=4))

        # Generate car simulator with llc_wcar.
        if llc_wcar >= 0:
            result = ControlModule.gencarsim(llc_wcar, args.output)
            if 0 != result.returncode:
                sys.stderr.write(result.stderr.decode('utf-8'))
        else:
            sys.stderr.write('llc_wcar[%d] is invalid\n' % llc_wcar)

class CollectModule:
    
    @staticmethod
    def service(args):
        pass

class SeginfoModule:
    
    @staticmethod
    def service(args):
        pass

class PWCETModule:

    @staticmethod
    def service(args):
        pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="pwcet analysis service.")

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
    control.add_argument('-o', '--output', metavar='', default='./shared_controller', 
                         help='path to save control task file, defualt is ./shared_controller')
    control.set_defaults(func=ControlModule.service)

    # Add subcommand collect.
    """
    collect     collect trace for task.
    positional argument     required    path to config of the target to collect and its contenders.
    -c, --clock=            optional    clock the tracer used, default is global, see /sys/kernel/tracing/trace_clock.
    -r, --repeat=           optional    generate multiple trace information by repeating each input, default is 20.
    """
    collect = subparsers.add_parser('collect', help='collect trace for task')
    collect.set_defaults(func=CollectModule.service)

    # Add subcommand seginfo.
    """
    seginfo     dump trace/seginfo, and generate a new seginfo.
    positional argument     ignored
    -t, --trace-file=       repeated    path to trace file(separated by ',' or provide multiple option).
    -s, --seginfo=          repeated    path to segment info(separated by ',' or provide multiple option).
    -m, --strip-mode=       repeated    choose time or callinfo or both to strip(separated by ',' or provide multiple option).
    """
    seginfo = subparsers.add_parser('seginfo', help='dump trace/seginfo, and generate a new seginfo')
    seginfo.set_defaults(func=SeginfoModule.service)

    # Add subcommand pwcet.
    """
    pwcet       generate pwcet result, build arguments of extreme distribution for segment and expression for function.
    positional argument     reuqired    path to segment info.
    -f, --function=         repeated    target functions(separated by ',' or provide multiple option) to generate, default is main only.
    -t, --evt-type=         optional    choose type of EVT family(GEV or GPD), default is GPD.
    -F, --force             optional    force to rebuild arguments of extreme distribution and expressions, even if they are already exist.
    -p, --prob=             repeated    exceedance probability, default is 1e-6.
    -v, --verbose           optional    generate pwcet curve of each function.
    -o, --output=           optional    path to output directory to save modified segment info and intermediate result, default is current dir.
    """
    pwcet = subparsers.add_parser('pwcet', help='generate pwcet result, build arguments of extreme distribution for segment and expression for function')
    pwcet.set_defaults(func=PWCETModule.service)

    # Parse arguments.
    args = parser.parse_args()

    # Process subcommands.
    if not hasattr(args, 'func'):
        parser.print_help()
    else:
        try:
            args.func(args)
        except Exception as error:
            print(traceback.print_exc())
