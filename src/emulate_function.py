#@keybinding alt shift e
#@menupath Emulate.Function
#@description An emulator frontend for Ghidra
from plugin import EmulatorPlugin

class DucktapedHelper:
    def __init__(self):
        self.monitor = monitor
        self.askString = askString
duck_helper = DucktapedHelper()

tool = state.getTool()
emulator_plugin = EmulatorPlugin(duck_helper, tool, True, True, True)
tool.addPlugin(emulator_plugin)