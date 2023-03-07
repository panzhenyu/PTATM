import EVTTool, argparse

"""
Usage: python3 genpwcet.py command [options] file
Generate pwcet estimate/curve for target functions.

[command]
    image           generate pwcet curve for each function.
    value           generate pwcet estimate for each function.
    symbol          generate symbolic trace file with each segment represented by GEV/GPD parameters.

[options]
    -o, --output    Output file to save result, default value: ${file}_pwcet.png for image mode and stdout for value mode.
    -f, --func      Target functions to generate pwcet, splited by ',' and default is main.
    -p, --prob      Exceedance probability, ignored in image mode, default is 1e-6.
    -t, --type      Choost type of EVT family(GEV or GPD), default is GPD.

[symbolic trace]
    The format of symbolic trace is almost as same as json trace(See TraceTool.JsonTraceSerializer or dumptrace.py):
        {
            "evt": "GPD",
            "func": {
                "main": {
                    // probe: time list
                    "main__0": {
                        "normcost": [1], (main__1 - main__0)
                        "nrcallee": {}
                    }
                }
            }
        }
"""

if __name__ == "__main__":
    raw_data = [
        61256933, 48096137, 47910470, 47691860, 47643836, 47370786, 47340414, 46983683, 46944760, 46899394, 46840381, 46828462, 46791887, 46678365, 46547132, 
        46531022, 46522973, 46517247, 46483128, 46453277, 46388158, 46370840, 46336187, 46220102, 46164678, 46153326, 46082580, 45975691, 45973001, 45970835, 
        45956649, 45887595, 45878599, 45868731, 45861109, 45784097, 45780270, 45744384, 45731700, 45697291, 45600591, 45595585, 45482988, 45474591, 45468955, 
        45468185, 45467253, 45446415, 45437051, 45436279, 45434349, 45423080, 45358307, 45273643, 45176924, 45176222, 45175596, 45157890, 45124597, 45121179, 
        45083091, 45061450, 45058042, 45041096, 45037095, 45025436, 45005427, 44996894, 44990941, 44982783, 44965970, 44963873, 44953902, 44947947, 44945259, 
        44943638, 44927849, 44926476, 44922766, 44918370, 44915151, 44904194, 44892244, 44868627, 44866067, 44864837, 44861809, 44861210, 44857971, 44856021, 
        44851393, 44847057, 44841344, 44840585, 44838506, 44836983, 44836307, 44835418, 44834696, 44832856
    ]
    
    func = EVTTool.Pareto()
    if not func.set_rawdata(raw_data).fit():
        print(func.err_msg)
    else:
        print(func.evt_func.kwds)
        print(func.cvm())
