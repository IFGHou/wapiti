class Attack:
    """
    This class represents an attack, it must be extended
    for any class which implements a new type of attack
    """
    verbose = 0
    color = 0
    reportGen = None
    HTTP = None

    def __init__(self,HTTP,reportGen):
        self.HTTP = HTTP
        self.reportGen = reportGen

    def setVerbose(self,verbose):
        self.verbose = verbose

    def setColor(self):
        self.color = 1