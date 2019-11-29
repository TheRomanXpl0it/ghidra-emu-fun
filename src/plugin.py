
from ghidra.app.plugin import ProgramPlugin
from ghidra.app.script import GhidraState
from ghidra.program.util import ProgramSelection
from ghidra.program.model.address import AddressSet

from gui import EmulatorComponentProvider
from emulator import Emulator, EmulatorState

import itertools

# from ghidra.util.task import Task
# import time
# class Foo(Task):
#     def run(self, monitor):
#         print "Yo"
#         monitor.clearCanceled()
#         monitor.setCancelEnabled(True)
#         monitor.initialize(10)
#         monitor.setMessage("Foo")
#         monitor.show(0)
#         monitor.setShowProgressValue(True)

#         for i in range(10):
#             print i
#             time.sleep(0.5)
#             monitor.setProgress(i)

class EmulatorPlugin(ProgramPlugin):
    def __init__(self, duck_helper, tool, *args):
        super(EmulatorPlugin, self).__init__(tool, *args)
        self.duck_helper = duck_helper
        self.emulator = None
        self.component = EmulatorComponentProvider(self)
        tool.addComponentProvider(self.component, True)

    # Ducky stuff
    def getMonitor(self):
        return self.duck_helper.monitor
    def askString(self, *args):
        return self.duck_helper.askString(*args)

    def getGhidraState(self):
        return GhidraState(self.getTool(), self.getTool().getProject(), self.getCurrentProgram(), self.getProgramLocation(), self.getProgramSelection(), self.getProgramHighlight())

    def getEmulator(self, state=None):
        return Emulator(self, state)

    def syncView(self, address=None):
        if address is None: address = self.state.getCurrentAddress()
        self.state.setCurrentAddress(address)
        self.state.setCurrentSelection(ProgramSelection(AddressSet(address)))

    def getCurrentFn(self, state=None):
        if state is None: state = self.state
        return "%s" % state.currentProgram.getFunctionManager().getFunctionContaining(state.getCurrentAddress())

    def doStart(self):
        self.state = self.getGhidraState()
        self.component.setStatus("Initializing @ %s" % self.getCurrentFn())
        self.initEmulator()
        self.emulator.initFunctionParameters()
        self.emulator.start()
        self.syncView()
        self.component.setStatus("Started @ %s" % self.getCurrentFn())
    
    def initEmulator(self, state=None):
        self.emulator = self.getEmulator(state)

    def doCmd(self):
        cmds = self.component.panel_input.getText()
        if self.emulator is None:
            self.doStart()

        if self.emulator.input_wildcards:
            self.doCmdFuzzing(cmds)
        else:
            self.emulator.executeCmds(cmds)
        self.component.panel_input.selectAll()
    
    def doCmdFuzzing(self, cmds):
        # from ghidra.util.task import TaskDialog
        # t = Foo("Sup")
        # monitor = TaskDialog(t)
        # t.monitoredRun(monitor)

        # return
        
        input_wildcards = self.emulator.input_wildcards
        init_state = cloneGhidraState(self.getGhidraState())
        domain = [range(0x100) for _ in range(len(input_wildcards))]
        # domain = [[0x2e-1, 0x2e, 0x2e+1] for _ in range(len(input_wildcards))]

        for vals in itertools.product(*domain):
            self.emulator.initEmulator(init_state.getCurrentProgram(), init_state.getCurrentAddress(), False)
            self.emulator.start({k:asByte(v) for k,v in zip(input_wildcards,vals)})
            self.emulator.executeCmds(cmds)

def asByte(v):
    if type(v) == type(""):
        if len(v) == 1:
            return "%02x" % ord(v)
        return v
    return "%02x" % v

def cloneGhidraState(state):
    return GhidraState(state.getTool(), state.getTool().getProject(), state.getCurrentProgram(), state.getCurrentLocation(), state.getCurrentSelection(), state.getCurrentHighlight())