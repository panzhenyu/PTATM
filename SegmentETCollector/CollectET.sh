CURRENT_USER=`whoami`
TRACE_ROOT=/sys/kernel/tracing
TRACE_FILE=${TRACE_ROOT}/trace
EVENTS_ROOT=${TRACE_ROOT}/events

HELP="usage: sudo bash thisfile uprobe1 uprobe2 binary args."

# Check out root privilege.
if [ $CURRENT_USER != "root" ]; then
    echo "Current user is ${CURRENT_USER}, run this file with root privilege."
    echo ${HELP}
    exit 1
elif [ $# -lt 3 ]; then
    echo ${HELP}
    exit 2
fi

UPROBE1=$1
UPROBE2=$2
BINARY=$3
ARGS=${@:4}

EnableUprobe() {
    # [in] param1: path to event switch
    if [ $# != 1 ]; then
        return 1
    fi
    echo 1 > $1
    return 0
}

DisableUprobe() {
    # [in] param1:path to event switch
    if [ $# != 1 ]; then
        return 1
    fi
    echo 0 > $1
    return 0
}

RemoveUprobe() {
    # [in] param1: uprobe
    
    if [ $# != 1 ]; then
        return 1
    fi

    perf probe -d $1 &> /dev/null
    return 0
}

ClearTrace() {
    echo > ${TRACE_FILE}
    return 0
}

# Check arguments.
if [ ! -f ${BINARY} ]; then
    echo "Cannot find binary file ${BINARY}."
    exit 3
fi

# Prepare variables.
GROUP="ETCG"
ORIG_TRACE=`cat ${TRACE_ROOT}/tracing_on`
ORIG_CLOCK=`cat ${TRACE_ROOT}/trace_clock | grep -P "\[.*?\]" -o`

# 1. Initialize uprobes.
if ! perf probe -x ${BINARY} -a ${GROUP}:UPROB1=${UPROBE1} &> /dev/null; then
    echo "Failed to add probe ${UPROBE1}."
    RemoveUprobe ${GROUP}:*
    exit 5
fi
if ! perf probe -x ${BINARY} -a ${GROUP}:UPROB2=${UPROBE2} &> /dev/null; then
    echo "Failed to add probe ${UPROBE2}."
    RemoveUprobe ${GROUP}:*
    exit 6
fi

# 2. Initialize trace environment.
echo 1 > ${TRACE_ROOT}/tracing_on
echo x86-tsc > ${TRACE_ROOT}/trace_clock
DisableUprobe ${EVENTS_ROOT}/enable
EnableUprobe ${EVENTS_ROOT}/${GROUP}/enable

# 3. Collect data.
ClearTrace
ENTRYLINE=$(expr 1 + `cat ${TRACE_FILE} | wc -l`)
if ${BINARY} ${ARGS} &> /dev/null; then
    cat ${TRACE_FILE} | tail -n +${ENTRYLINE}
fi
ClearTrace

# 4. Recover trace environment.
DisableUprobe ${EVENTS_ROOT}/${GROUP}/enable
echo ${ORIG_CLOCK:1:-1} > ${TRACE_ROOT}/trace_clock
echo ${ORIG_TRACE} > ${TRACE_ROOT}/tracing_on

# 5. Destory uprobes.
RemoveUprobe ${GROUP}:*
