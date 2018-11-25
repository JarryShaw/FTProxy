import wx
import ftcap
import os
import json


class mainFrame(wx.Frame):
    def __init__(self, Parent=None, ID=-1, Title="Transparent Proxy Manager", Pos=(100, 100), Size=(800, 600)):
        wx.Frame.__init__(self, parent=Parent, id=ID, title=Title, pos=Pos, size=Size)

        self.topSplitter = wx.SplitterWindow(self, -1, style=wx.SP_3D)
        self.secondSplitter = wx.SplitterWindow(self.topSplitter, -1, style=wx.SP_3D)
        self.thirdSplitter = wx.SplitterWindow(self.secondSplitter, -1, style=wx.SP_3D)
        self.fourthSplitter = wx.SplitterWindow(self.thirdSplitter, -1, style=wx.SP_3D)
        self.policyPanel = wx.Panel(self.topSplitter, -1)
        self.policyGridBag = wx.GridBagSizer(0, 0)
        self.listPanel = wx.Panel(self.secondSplitter, -1)
        self.flowPanel = wx.Panel(self.thirdSplitter, -1)
        self.detailPanel = wx.Panel(self.fourthSplitter, -1)
        self.buttonPanel = wx.Panel(self.fourthSplitter, -1)
        self.sessionList = wx.ListBox(self.listPanel, -1, choices=[], style=wx.LB_SINGLE)
        self.refresh = wx.Button(self.listPanel, -1, label="刷新")
        self.flowList = wx.ListCtrl(self.flowPanel, -1, style=wx.LC_REPORT)
        self.clientBlacklist = wx.TextCtrl(self.policyPanel, -1, style=wx.TE_MULTILINE)
        self.serverBlacklist = wx.TextCtrl(self.policyPanel, -1, style=wx.TE_MULTILINE)
        self.userBlacklist = wx.TextCtrl(self.policyPanel, -1, style=wx.TE_MULTILINE)
        self.clientBlacklistApply = wx.Button(self.policyPanel, -1, label="应用")
        self.serverBlacklistApply = wx.Button(self.policyPanel, -1, label="应用")
        self.userBlacklistApply = wx.Button(self.policyPanel, -1, label="应用")
        self.clientInfo = wx.StaticText(self.detailPanel, -1, label="客户端信息")
        self.serverInfo = wx.StaticText(self.detailPanel, -1, label="服务器信息")
        self.username = wx.StaticText(self.detailPanel, -1, label="用户名")
        self.password = wx.StaticText(self.detailPanel, -1, label="密码")
        self.selectFile = wx.Choice(self.buttonPanel, -1, choices=[])
        self.extractFile = wx.Button(self.buttonPanel, -1, label="提取文件")

        self.sessions = []
        self.files = []

        # self.menuBar = wx.MenuBar()
        self.statusBar = self.CreateStatusBar()
        self.toolBar = self.CreateToolBar(wx.TB_HORIZONTAL | wx.TB_TEXT)
        self.initGUI()

    def initGUI(self):
        # self.initMenuBar()
        # self.initStatusBar()
        # self.initToolBar()
        self.initPanel()

        self.Bind(wx.EVT_SIZE, self.onResize)
        self.refresh.Bind(wx.EVT_BUTTON, self.onRefresh)
        self.sessionList.Bind(wx.EVT_LISTBOX, self.onSelect)
        self.extractFile.Bind(wx.EVT_BUTTON, self.onExtractFile)
        self.clientBlacklistApply.Bind(wx.EVT_BUTTON, self.onApplyClientBlacklist)
        self.serverBlacklistApply.Bind(wx.EVT_BUTTON, self.onApplyServerBlacklist)
        self.userBlacklistApply.Bind(wx.EVT_BUTTON, self.onApplyUserBlacklist)

        self.onRefresh(None)

    # def initMenuBar(self):
    #     self.SetMenuBar(self.menuBar)
    #     self.Bind(wx.EVT_MENU, self.barHandler, self.menuBar)

    # def initStatusBar(self):
    #     self.statusBar.SetFieldsCount(2)
    #     self.statusBar.SetStatusWidths([1, 4])
    #
    #     self.SetStatusBar(self.statusBar)

    # def initToolBar(self):
    #     self.SetToolBar(self.toolBar)
    #     self.Bind(wx.EVT_TOOL, self.barHandler, self.toolBar)

    def initPanel(self):
        self.fourthSplitter.SplitVertically(self.detailPanel, self.buttonPanel, 100)
        self.fourthSplitter.SetSashGravity(0.5)
        self.thirdSplitter.SplitHorizontally(self.flowPanel, self.fourthSplitter, 250)
        self.thirdSplitter.SetSashGravity(0.5)
        self.secondSplitter.SplitVertically(self.listPanel, self.thirdSplitter, 200)
        self.secondSplitter.SetSashGravity(0.5)
        self.topSplitter.SplitHorizontally(self.secondSplitter, self.policyPanel, 350)
        self.topSplitter.SetSashGravity(0.5)

        listSizer = wx.GridBagSizer(0, 0)
        sessionListTitle = wx.StaticText(self.listPanel, -1, '对话列表', style=wx.ALIGN_CENTER)
        listSizer.Add(sessionListTitle, pos=(0, 0), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        listSizer.Add(self.sessionList, pos=(1, 0), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        listSizer.AddGrowableRow(1)
        listSizer.AddGrowableCol(0)
        listSizer.Add(self.refresh, pos=(2, 0), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        self.listPanel.SetSizer(listSizer)

        flowSizer = wx.BoxSizer(wx.VERTICAL)
        flowListTitle = wx.StaticText(self.flowPanel, -1, '对话内容', style=wx.ALIGN_CENTER)
        flowSizer.Add(flowListTitle, proportion=0, flag=wx.EXPAND | wx.ALL, border=5)
        self.flowList.InsertColumn(0, "Time")
        self.flowList.InsertColumn(1, "SrcIP")
        self.flowList.InsertColumn(2, "SrcPort")
        self.flowList.InsertColumn(3, "DstIP")
        self.flowList.InsertColumn(4, "DstPort")
        self.flowList.InsertColumn(5, "Contents")
        flowSizer.Add(self.flowList, proportion=1, flag=wx.EXPAND | wx.ALL, border=5)
        self.flowPanel.SetSizer(flowSizer)

        policyGridSizer = wx.GridBagSizer(0, 0)
        clientBlacklistTitle = wx.StaticText(self.policyPanel, -1, '客户端黑名单', style=wx.ALIGN_CENTER)
        policyGridSizer.Add(clientBlacklistTitle, pos=(0, 0), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        policyGridSizer.Add(self.clientBlacklistApply, pos=(0, 1), span=(1, 1), flag=wx.ALIGN_CENTER, border=5)
        serverBlacklistTitle = wx.StaticText(self.policyPanel, -1, '服务器黑名单', style=wx.ALIGN_CENTER)
        policyGridSizer.Add(serverBlacklistTitle, pos=(0, 2), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        policyGridSizer.Add(self.serverBlacklistApply, pos=(0, 3), span=(1, 1), flag=wx.ALIGN_CENTER, border=5)
        userBlacklistTitle = wx.StaticText(self.policyPanel, -1, '用户黑名单', style=wx.ALIGN_CENTER)
        policyGridSizer.Add(userBlacklistTitle, pos=(0, 4), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        policyGridSizer.Add(self.userBlacklistApply, pos=(0, 5), span=(1, 1), flag=wx.ALIGN_CENTER, border=5)
        policyGridSizer.Add(self.clientBlacklist, pos=(1, 0), span=(1, 2), flag=wx.EXPAND | wx.ALL, border=5)
        policyGridSizer.Add(self.serverBlacklist, pos=(1, 2), span=(1, 2), flag=wx.EXPAND | wx.ALL, border=5)
        policyGridSizer.Add(self.userBlacklist, pos=(1, 4), span=(1, 2), flag=wx.EXPAND | wx.ALL, border=5)
        # policyGridSizer.AddMany([(clientBlacklistTitle, 0, wx.ALIGN_CENTER), (serverBlacklistTitle, 0, wx.ALIGN_CENTER), (userBlacklistTitle, 0, wx.ALIGN_CENTER),
        #                          (self.clientBlacklist, 0, wx.EXPAND), (self.serverBlacklist, 0, wx.EXPAND), (self.userBlacklist, 0, wx.EXPAND)])
        policyGridSizer.AddGrowableRow(1)
        policyGridSizer.AddGrowableCol(0)
        policyGridSizer.AddGrowableCol(1)
        policyGridSizer.AddGrowableCol(2)
        policyGridSizer.AddGrowableCol(3)
        policyGridSizer.AddGrowableCol(4)
        policyGridSizer.AddGrowableCol(5)
        # policyBoxSizer = wx.BoxSizer(wx.HORIZONTAL)
        # policyBoxSizer.Add(policyGridSizer, proportion=1, flag=wx.ALL | wx.EXPAND, border=15)
        self.policyPanel.SetSizer(policyGridSizer)

        sessionDetailGridSizer = wx.GridBagSizer(0, 0)
        clientInfoTitle = wx.StaticText(self.detailPanel, -1, '客户端信息', style=wx.ALIGN_CENTER)
        sessionDetailGridSizer.Add(clientInfoTitle, pos=(0, 0), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        sessionDetailGridSizer.Add(self.clientInfo, pos=(0, 1), span=(1, 2), flag=wx.EXPAND | wx.ALL, border=5)
        serverInfoTitle = wx.StaticText(self.detailPanel, -1, '服务器信息', style=wx.ALIGN_CENTER)
        sessionDetailGridSizer.Add(serverInfoTitle, pos=(1, 0), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        sessionDetailGridSizer.Add(self.serverInfo, pos=(1, 1), span=(1, 2), flag=wx.EXPAND | wx.ALL, border=5)
        sessionDetailGridSizer.AddGrowableCol(1)
        usernameTitle = wx.StaticText(self.detailPanel, -1, '用户名', style=wx.ALIGN_CENTER)
        sessionDetailGridSizer.Add(usernameTitle, pos=(0, 3), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        sessionDetailGridSizer.Add(self.username, pos=(0, 4), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        passwordTitle = wx.StaticText(self.detailPanel, -1, '密码', style=wx.ALIGN_CENTER)
        sessionDetailGridSizer.Add(passwordTitle, pos=(1, 3), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        sessionDetailGridSizer.Add(self.password, pos=(1, 4), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        sessionDetailGridSizer.AddGrowableCol(4)
        sessionDetailGridSizer.AddGrowableRow(0)
        sessionDetailGridSizer.AddGrowableRow(1)
        self.detailPanel.SetSizer(sessionDetailGridSizer)

        sessionFileGridSizer = wx.GridBagSizer(0, 0)
        sessionFileGridSizer.Add(self.selectFile, pos=(0, 0), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        sessionFileGridSizer.Add(self.extractFile, pos=(1, 0), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        sessionFileGridSizer.AddGrowableCol(0)
        sessionFileGridSizer.AddGrowableRow(0)
        sessionFileGridSizer.AddGrowableRow(1)
        self.buttonPanel.SetSizer(sessionFileGridSizer)

    def barHandler(self):
        pass

    def onRefresh(self, evt):
        self.sessions = []
        fileList = ['./record/'+x for x in os.listdir('./record/')]
        for i in fileList:
            self.sessions.append(ftcap.reader(i))

        self.sessionList.Clear()
        for i in self.sessions:
            self.sessionList.Append(i[0].info.time.ctime())

        self.sessionList.SetSelection(0)
        self._selectSessionList(0)

    def onSelect(self, evt):
        selection = self.sessionList.GetSelection()
        self._selectSessionList(selection)

    def _selectSessionList(self, selection):
        self.flowList.DeleteAllItems()
        self.clientInfo.SetLabel(str(self.sessions[selection][0].info.client))
        self.serverInfo.SetLabel(str(self.sessions[selection][0].info.server))
        username = None
        password = None
        self.files = {}
        fileTransferring = False
        fileName = None
        fileContent = None
        for i in self.sessions[selection][1]:
            recvData = str(i.info.ftp.raw if 'ftp' in i else i.info.raw.packet)[2:-1]
            self.flowList.Append((i.info.time.ctime(), i.info.src.ip, i.info.src.port, i.info.dst.ip, i.info.dst.port, recvData))
            if 'ftp' in i:
                if i.info.ftp.type == 'request':
                    if i.info.ftp.command.name == 'USER':
                        username = i.info.ftp.arg
                    elif i.info.ftp.command.name == 'PASS':
                        password = i.info.ftp.arg
                    elif i.info.ftp.command.name == 'RETR':
                        fileName = i.info.ftp.arg
                        fileTransferring = True
                        fileContent = b''
                if i.info.ftp.type == 'response':
                    if i.info.ftp.code == 226 and fileTransferring:
                        fileTransferring = False
                        self.files[fileName[1:]] = fileContent
            else:
                if fileTransferring:
                    fileContent += i.info.raw.packet
        self.selectFile.SetItems(list(self.files.keys()))

        self.username.SetLabel(username)
        self.password.SetLabel(password)

    def onResize(self, evt):
        width, height = evt.GetSize()
        self.flowList.SetColumnWidth(0, 40)
        self.flowList.SetColumnWidth(1, 100)
        self.flowList.SetColumnWidth(2, 60)
        self.flowList.SetColumnWidth(3, 100)
        self.flowList.SetColumnWidth(4, 60)
        self.flowList.SetColumnWidth(5, (width-100)/8*3)

        evt.Skip()

    def onExtractFile(self, evt):
        selectFile = self.selectFile.GetStringSelection()
        if selectFile:
            file_wildcard = "*"
            dlg = wx.FileDialog(self, "Save as...",
                                os.getcwd(),
                                style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT,
                                wildcard=file_wildcard)
            dlg.SetFilename(selectFile)
            if dlg.ShowModal() == wx.ID_OK:
                path = dlg.GetPath()
                with open(path, 'wb') as f:
                    f.write(self.files[selectFile])
        else:
            dlg = wx.MessageDialog(None, u'未选择文件', u'提示')
            dlg.ShowModal()
            dlg.Destroy()

    def onApplyClientBlacklist(self, evt):
        value = self.clientBlacklist.GetValue()
        blacklist = []
        for i in value.split('\n'):
            blacklist.append(i)
        with open('clientBlacklist.json', 'w') as f:
            json.dump(blacklist, f)

    def onApplyServerBlacklist(self, evt):
        value = self.serverBlacklist.GetValue()
        blacklist = []
        for i in value.split('\n'):
            blacklist.append(i)
        with open('serverBlacklist.json', 'w') as f:
            json.dump(blacklist, f)

    def onApplyUserBlacklist(self, evt):
        value = self.userBlacklist.GetValue()
        blacklist = []
        for i in value.split('\n'):
            blacklist.append(i)
        with open('userBlacklist.json', 'w') as f:
            json.dump(blacklist, f)


class Firewall(wx.App):
    def OnInit(self):
        self.myframe = mainFrame()
        self.SetTopWindow(self.myframe)
        self.myframe.Centre()
        self.myframe.Show(True)
        return True

# class SnifferThread(Thread):
#     def __init__(self, Iface, Prn, StopFilter):
#         Thread.__init__(self)
#         self.sniffer = sniff(iface=Iface, prn=Prn, stop_filter=StopFilter)


if __name__ == '__main__':
    app = Firewall()
    app.MainLoop()
