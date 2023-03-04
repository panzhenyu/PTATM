CURRENT_USER=`whoami`
TRACE_ROOT=/sys/kernel/tracing
TRACE_FILE=${TRACE_ROOT}/trace
EVENTS_ROOT=${TRACE_ROOT}/events

HELP="usage: sudo bash thisfile segment input output iter owner."

# Check out root privilege.
if [ $CURRENT_USER != "root" ]; then
    echo "Current user is ${CURRENT_USER}, run this file with root privilege."
    echo ${HELP}
    exit 1
elif [ $# != 3 ]; then
    echo ${HELP}
    exit 2
fi

PLAN=$1
OUTPUT=$2
OWNER=$3

# Check arguments.
if [ ! -f ${PLAN} ]; then
    echo "Cannot find file ${PLAN}."
    exit 3
fi

if [ -d ${OUTPUT} -o -f ${OUTPUT} ]; then
    echo "Output ${OUTPUT} is already exist."
    exit 4
fi

if ! id -u ${OWNER} > /dev/null 2>&1; then
    echo "Can't find user ${OWNER}."
    exit 5
fi

# Fetch binary file and uprobes from ${PLAN}
BINARY_LINENO=$(expr 1 + `grep -xn '\[binary\]' ${PLAN} | awk -F: '{print $1}'`)
if [ 0 != $? ]; then
    echo "Can't find [binary] in ${PLAN}."
    exit 6
fi

UPROBE_LINENO=$(expr 1 + `grep -xn '\[uprobe\]' ${PLAN} | awk -F: '{print $1}'`)
if [ 0 != $? ]; then
    echo "Can't find [uprobe] in ${PLAN}."
    exit 7
fi

unset UPROBE
BINARY=`sed -n ${BINARY_LINENO}p ${PLAN}`
UPROBE=(`tail +${UPROBE_LINENO} ${PLAN}`)

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

AddUprobe() {
    # [in] param1: binary
    # [in] param2: uprobe

    if [ $# != 2 ]; then
        return 1
    fi

    perf probe -x $1 -a $2
    return 0
}

RemoveUprobe() {
    # [in] param1: uprobe
    
    if [ $# != 1 ]; then
        return 1
    fi

    perf probe -d $1
    return 0
}

ClearTrace() {
    echo > ${TRACE_FILE}
    return 0
}

CollectTrace() {
    # [in] param1: num of line
    # [in] param2: output

    if [ $# != 2 ]; then
        return 1
    fi

    cat ${TRACE_FILE} | tail -n $1 > $2
    # Clear trace file.
    ClearTrace
    return 0
}

# Prepare variables.
GROUP="ETCG"
EVENT_PREFIX="EVENT"
ORIG_TRACE=`cat ${TRACE_ROOT}/tracing_on`
ORIG_CLOCK=`cat ${TRACE_ROOT}/trace_clock | grep -P "\[.*?\]" -o`

# 1. Initialize uprobes.
echo "Collect execution time for ${BINARY} with ${#UPROBE[*]} uprobe."
for ((i=0; i<${#UPROBE[*]}; ++i)); do
    AddUprobe ${BINARY} ${GROUP}:${EVENT_PREFIX}${i}=${UPROBE[$i]}
done

# 2. Initialize trace environment.
echo 1 > ${TRACE_ROOT}/tracing_on
echo x86-tsc > ${TRACE_ROOT}/trace_clock
DisableUprobe ${EVENTS_ROOT}/enable
EnableUprobe ${EVENTS_ROOT}/${GROUP}/enable
ClearTrace

# 3. Collect data.
${BINARY} &> /dev/null

if [ 0 == $? ]; then
    CollectTrace ${#UPROBE[*]} ${OUTPUT}
fi

# 4. Recover trace environment.
ClearTrace
DisableUprobe ${EVENTS_ROOT}/${GROUP}/enable
echo ${ORIG_CLOCK:1:-1} > ${TRACE_ROOT}/trace_clock
echo ${ORIG_TRACE} > ${TRACE_ROOT}/tracing_on


# 5. Destory uprobes.
RemoveUprobe ${GROUP}:*
