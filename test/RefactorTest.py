import sys
sys.path.append("..")

import angr
from CFG2Segment.SFG import *
from CFG2Segment.BasicStruct import *
from CFG2Segment.ControlFlowRefactor import *

# automotive
basicmath_large = "/home/pzy/project/mibench/automotive/basicmath/basicmath_large"
basicmath_small = "/home/pzy/project/mibench/automotive/basicmath/basicmath_small"
bitcnts = "/home/pzy/project/mibench/automotive/bitcount/bitcnts"
qsort_large = "/home/pzy/project/mibench/automotive/qsort/qsort_large"
qsort_small = "/home/pzy/project/mibench/automotive/qsort/qsort_small"
susan = "/home/pzy/project/mibench/automotive/susan/susan"
# consumer
# jpeg = "/home/pzy/project/mibench/consumer/jpeg/jpeg-6a/cjpeg"
# lame = "/home/pzy/project/mibench/consumer/lame/lame3.70/lame"
# mad = "/home/pzy/project/mibench/consumer/mad/mad-0.14.2b/madplay"
# network
dijkstra_large = "/home/pzy/project/mibench/network/dijkstra/dijkstra_large"
dijkstra_small = "/home/pzy/project/mibench/network/dijkstra/dijkstra_small"
# office
search_large = "/home/pzy/project/mibench/office/stringsearch/search_large"
search_small = "/home/pzy/project/mibench/office/stringsearch/search_small"
# security
bf = "/home/pzy/project/mibench/security/blowfish/bf"
sha = "/home/pzy/project/mibench/security/sha/sha"
# telecomm
adpcm = "/home/pzy/project/mibench/telecomm/adpcm/bin/rawcaudio"
crc = "/home/pzy/project/mibench/telecomm/CRC32/crc"
fft = "/home/pzy/project/mibench/telecomm/FFT/fft"
gsm_toast = "/home/pzy/project/mibench/telecomm/gsm/bin/toast"
gsm_untoast = "/home/pzy/project/mibench/telecomm/gsm/bin/untoast"

benchmark = "/home/pzy/project/PTATM/benchmark/benchmark"
test = "/home/pzy/project/PTATM/benchmark/test"

p = angr.Project(benchmark, load_options={'auto_load_libs': False})
cfg = p.analyses.CFGFast()
mycfg = CFG.fromAngrCFG(cfg)

refactor = FunctionalCFGRefactor()
print(refactor.refactor(mycfg))

graph = {hex(func.addr):[hex(addr) for addr in func.callees] for func in mycfg.functions.values()}
print(graph)

keys = list(graph.keys())
print(GraphTools.topologicalSort(graph, keys))