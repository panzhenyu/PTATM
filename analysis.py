
helper = """
Usage: python3 analysis.py command [options] ...
Provide pwcet analysis service.

[command]
    segment     parse binary file into segment.
        positional argument     required    path to binary file.
        -f, --func=             repeated    interested functions(separated by ',' or provide multiple option), default is main only.
        -s, --max-seg=          optional    max segment num, default is 2.

        [output]
            stdout: probes separate by ','.
    
    control     generate shared resource controller of taskset.
        positional argument     required    path to file includes parallel tasks.
        -w, --llc-wcar=         optional    use llc wcar to generate resource controller.
        -F, --force             optional    force to measure wcar for each task.
        -o, --output=           optional    path to save control task file, defualt is ./shared-controller

        [input]
            [positional argument]
                File is in json format.
                [
                    {
                        "dir": working directory,
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
        -c, --clock=            optional    clock the tracer used, default is x86-tsc, see /sys/kernel/tracing/trace_clock.
        -r, --repeat=           optional    generate multiple trace information by repeating each input, default is 20.
        
        [input]
            [positional argument]
                File is in json format.
                {
                    "target": {
                        "core": core number used by target,
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
                        "core": core number used by contender,
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
        -f, --func=             repeated    target functions(separated by ',' or provide multiple option) to generate, default is main only.
        -t, --evt-type=         optional    choose type of EVT family(GEV or GPD), default is GPD.
        -F, --force             optional    force to rebuild arguments of extreme distribution and expressions, even if they are already exist.
        -p, --prob=             optional    exceedance probability, default is 1e-6.
        -v, --verbose           optional    generate pwcet curve of each function.
        -o, --output=           optional    path to output directory to save modified segment info and intermediate result, default is current dir.

        [input]
            [positional argument]
                File of segment information in json format, see SegmentInforCollector/TraceTool.py for detail.

        [verbose]
            ${func}-pwcet.png: pwcet curve for ${func}.

        [output]
            stdout: pwcet under exceedance probability(prob).
        
        [note]
            We will save arguments of extreme distribution and expressions into the file provided 
            by positional argument, see PWCETGenerator/PWCETSolver.py for detail.
"""
