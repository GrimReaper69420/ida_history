import idaapi

# Importing Cutom classes
from ida_history.ida_history_idb_hooks import idb_hook
from ida_history.ida_history_idb_hooks import ida_hexrays_hook

class ida_history_plugmod_t(idaapi.plugmod_t):
    def __init__(self):
        super().__init__()
        self.idb_hook = idb_hook()
        self.ida_hexrays_hook = ida_hexrays_hook()
        print("[IDA Plugin] Files initilized")


    
    def run(self, arg):
        self.idb_hook.hook()
        self.ida_hexrays_hook.hook()
        print("[IDA Plugin] All the functions Hooked")
        return 0

    def __del__(self):
        print("[IDA Plugin] Plugin terminated, Database Closed")
        self.idb_hook.unhook()
        self.ida_hexrays_hook.unhook()
        print("[IDA Plugin] All the hooks removed")


# FOr the loading of Plugin
class ida_history_plugin_t(idaapi.plugin_t):
#    help = ""
    flags = idaapi.PLUGIN_MULTI
    comment = "IDA History Plugin, It tracks changes done to the DB"
    wanted_name = "IDA History"
    wanted_hotkey = "Ctrl-H"

    def init(self):
        return ida_history_plugmod_t()

def PLUGIN_ENTRY():
    return ida_history_plugin_t()


####################################
# OLD Main for testing Plugin
#####################################

# if __name__ == "__main__":
#     idb_hook = idb_hook()
#     ida_hexrays_hook = ida_hexrays_hook()
    
#     idb_hook.hook()
#     ida_hexrays_hook.hook()