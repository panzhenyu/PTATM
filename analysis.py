
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
        -o, --output=           optional    path to output directory to save control task as well as intermediate result, default is current dir.

        [input]
            [positional argument]
                File is in json format.
                {
                    "tasks": {
                        "dir": working directory,
                        "cmd": [
                            "command1", 
                            "command2", 
                            ...
                        ],
                    },
                    "llc-wcar": {
                        "command1": [wcar1, wcar2],
                        ...
                    }
                }
            [llc-wcar]
                An integer hints a cache set access occurs every ${llc-wcar} instructions.

        [output]
            stdout: none.
            shared-control: shared resource controller.

        [note]
            We will save wcar result into the file provided by positional argument.

    collect     collect trace for task.
        positional argument     ignored
        -t, --task=             required    path to config of the task to collect, which contains contains binary file, probes and input vectors.
        -C, --core-no=          repeated    core number(separated by ',' or provide multiple option) to place the task and shared resource control task.
        -T, --control-task=     optional    path to shared resource control task.
        -c, --clock=            optional    clock the tracer used, default is x86-tsc, see /sys/kernel/tracing/trace_clock.
        -r, --repeat=           optional    generate multiple trace information by repeating each input, default is 1.

        [limit]
            num of core-no must be greater than 0.
            control-task is required if num of --core-no larger than 1.
        
        [input]
            [task]
                File format.
                [binary]
                    path to binary file
                [probes]
                    probes splited with ','
                [inputs]
                    input arguments1
                    input arguments2
                    ...

        [output]
            stdout: trace info, trace format:
                [${command}]
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
