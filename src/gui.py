from javax.swing import AbstractAction, JPanel, JButton, JTextField, JLabel
from java.awt import GridBagLayout, GridBagConstraints
from ghidra.framework.plugintool import ComponentProviderAdapter

class EmulatorInputAction(AbstractAction):
    def __init__(self, ec):
        self.ec = ec
    def actionPerformed(self, e):
        self.ec.plugin.doCmd()

class EmulatorBtnAction(AbstractAction):
    def __init__(self, ec):
        self.ec = ec
    def actionPerformed(self, e):
        self.ec.plugin.doStart()

class EmulatorComponentProvider(ComponentProviderAdapter):
    def __init__(self, plugin):
        super(EmulatorComponentProvider, self).__init__(plugin.getTool(), "Emulator", "emulate_function")
        self.plugin = plugin

        self.panel = JPanel(GridBagLayout())
        c = GridBagConstraints()
        c.fill = GridBagConstraints.HORIZONTAL
        c.gridy = 0

        c.gridx = 0
        c.weightx = 0.8
        self.panel_label = JLabel("")
        self.panel.add(self.panel_label, c)

        c.gridx = 1
        c.weightx = 0.2
        self.panel_btn = JButton("Start")
        self.panel_btn.addActionListener(EmulatorBtnAction(self))
        self.panel.add(self.panel_btn, c)

        c.gridy = 1
        c.gridx = 0
        c.gridwidth = 2
        self.panel_input = JTextField()        
        self.panel_input.addActionListener(EmulatorInputAction(self))
        self.panel.add(self.panel_input, c)

        self.setStatus("Stopped")

    def getComponent(self):
		return self.panel

    def setStatus(self, status):
        self.panel_label.setText(status)


    # def isTransient(self):
    #     return True