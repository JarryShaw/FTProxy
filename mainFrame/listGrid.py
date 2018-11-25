import wx.grid as grid


class StudentInfoGridTable(grid.PyGridTableBase):
    def __init__(self, data):
        grid.PyGridTableBase.__init__(self)

        self.data = data
        self.colLabels = ['Client', 'Server']

        self.clientToServer = grid.GridCellAttr()
        self.clientToServer.SetReadOnly(True)
        self.clientToServer.SetBackgroundColour('yellow')
        self.serverToClient = grid.GridCellAttr()
        self.serverToClient.SetReadOnly(True)

    def GetAttr(self, row, col, kind):
        attr = [self.even, self.odd][row % 2]
        attr.IncRef()
        return attr

    def GetNumberRows(self):
        return len(self.datas)

    def GetNumberCols(self):
        return len(self.colLabels)

    def GetColLabelValue(self, col):
        return self.colLabels[col]

    def GetRowLabelValue(self, row):
        return str(row)

    def GetValue(self, row, col):
        return self.datas[row][col]
