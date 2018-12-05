# -*- coding: utf-8 -*-

import os

import wx

import ftcap
import policyManager


class mainFrame(wx.Frame):
    def __init__(self, parent=None, id=-1, title="Transparent Proxy Manager", pos=(100, 100), size=(900, 600)):
        # Initialize main frame
        wx.Frame.__init__(self, parent=parent, id=id, title=title, pos=pos, size=size)
        # Initialize objects
        self.topSplitter = wx.SplitterWindow(parent=self, id=-1, style=wx.SP_3D)
        self.secondSplitter = wx.SplitterWindow(parent=self.topSplitter, id=-1, style=wx.SP_3D)
        self.thirdSplitter = wx.SplitterWindow(parent=self.secondSplitter, id=-1, style=wx.SP_3D)
        self.fourthSplitter = wx.SplitterWindow(parent=self.thirdSplitter, id=-1, style=wx.SP_3D)
        self.policyPanel = wx.Panel(parent=self.topSplitter, id=-1)
        self.policyGridBag = wx.GridBagSizer(0, 0)
        self.listPanel = wx.Panel(parent=self.secondSplitter, id=-1)
        self.flowPanel = wx.Panel(parent=self.thirdSplitter, id=-1)
        self.detailPanel = wx.Panel(parent=self.fourthSplitter, id=-1)
        self.buttonPanel = wx.Panel(parent=self.fourthSplitter, id=-1)
        self.sessionList = wx.ListBox(parent=self.listPanel, id=-1, choices=[], style=wx.LB_SINGLE)
        self.refresh = wx.Button(parent=self.listPanel, id=-1, label="刷新")
        self.flowList = wx.ListCtrl(parent=self.flowPanel, id=-1, style=wx.LC_REPORT)
        self.clientBlacklist = wx.TextCtrl(parent=self.policyPanel, id=-1, style=wx.TE_MULTILINE)
        self.serverBlacklist = wx.TextCtrl(parent=self.policyPanel, id=-1, style=wx.TE_MULTILINE)
        self.userBlacklist = wx.TextCtrl(parent=self.policyPanel, id=-1, style=wx.TE_MULTILINE)
        self.fileBlacklist = wx.TextCtrl(parent=self.policyPanel, id=-1, style=wx.TE_MULTILINE)
        self.extensionBlacklist = wx.TextCtrl(parent=self.policyPanel, id=-1, style=wx.TE_MULTILINE)
        self.pathBlacklist = wx.TextCtrl(parent=self.policyPanel, id=-1, style=wx.TE_MULTILINE)
        self.sizeLimit = wx.TextCtrl(parent=self.policyPanel, id=-1)
        self.retrPolicy = wx.CheckBox(parent=self.policyPanel, id=-1, label="禁止下载")
        self.storPolicy = wx.CheckBox(parent=self.policyPanel, id=-1, label="禁止上传")
        self.policyApply = wx.Button(parent=self.policyPanel, id=-1, label="应用")
        self.clientInfo = wx.StaticText(parent=self.detailPanel, id=-1, label="客户端信息")
        self.serverInfo = wx.StaticText(parent=self.detailPanel, id=-1, label="服务器信息")
        self.username = wx.StaticText(parent=self.detailPanel, id=-1, label="用户名")
        self.password = wx.StaticText(parent=self.detailPanel, id=-1, label="密码")
        self.selectFile = wx.Choice(parent=self.buttonPanel, id=-1, choices=[])
        self.extractFile = wx.Button(parent=self.buttonPanel, id=-1, label="提取文件")
        # Initialize session list, file list, and policy list
        self.sessions = []
        self.files = []
        self.policy = None
        # Initialize GUI
        self.initGUI()

    def initGUI(self):
        # Set grid
        self.initPanel()
        # Bind events
        self.Bind(wx.EVT_SIZE, self.onResize)
        self.refresh.Bind(wx.EVT_BUTTON, self.onRefresh)
        self.sessionList.Bind(wx.EVT_LISTBOX, self.onSelect)
        self.extractFile.Bind(wx.EVT_BUTTON, self.onExtractFile)
        self.policyApply.Bind(wx.EVT_BUTTON, self.onApply)
        # Refresh panel
        self.onRefresh(None)

    def initPanel(self):
        # Split window
        self.fourthSplitter.SplitVertically(self.detailPanel, self.buttonPanel, 100)
        self.fourthSplitter.SetSashGravity(0.5)
        self.thirdSplitter.SplitHorizontally(self.flowPanel, self.fourthSplitter, 250)
        self.thirdSplitter.SetSashGravity(0.5)
        self.secondSplitter.SplitVertically(self.listPanel, self.thirdSplitter, 200)
        self.secondSplitter.SetSashGravity(0.5)
        self.topSplitter.SplitHorizontally(self.secondSplitter, self.policyPanel, 350)
        self.topSplitter.SetSashGravity(0.5)
        # Setup session list
        listSizer = wx.GridBagSizer(0, 0)
        sessionListTitle = wx.StaticText(parent=self.listPanel, id=-1, label='对话列表', style=wx.ALIGN_CENTER)
        listSizer.Add(sessionListTitle, pos=(0, 0), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        listSizer.Add(self.sessionList, pos=(1, 0), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        listSizer.AddGrowableRow(1)
        listSizer.AddGrowableCol(0)
        listSizer.Add(self.refresh, pos=(2, 0), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        self.listPanel.SetSizer(listSizer)
        # Setup flow list
        flowSizer = wx.BoxSizer(wx.VERTICAL)
        flowListTitle = wx.StaticText(parent=self.flowPanel, id=-1, label='对话内容', style=wx.ALIGN_CENTER)
        flowSizer.Add(flowListTitle, proportion=0, flag=wx.EXPAND | wx.ALL, border=5)
        self.flowList.InsertColumn(0, "Time")
        self.flowList.InsertColumn(1, "SrcIP")
        self.flowList.InsertColumn(2, "SrcPort")
        self.flowList.InsertColumn(3, "DstIP")
        self.flowList.InsertColumn(4, "DstPort")
        self.flowList.InsertColumn(5, "Contents")
        flowSizer.Add(self.flowList, proportion=1, flag=wx.EXPAND | wx.ALL, border=5)
        self.flowPanel.SetSizer(flowSizer)
        # Setup policy setting
        policyGridSizer = wx.GridBagSizer(0, 0)
        clientBlacklistTitle = wx.StaticText(parent=self.policyPanel, id=-1, label='客户端黑名单', style=wx.ALIGN_CENTER)
        policyGridSizer.Add(clientBlacklistTitle, pos=(0, 0), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        serverBlacklistTitle = wx.StaticText(parent=self.policyPanel, id=-1, label='服务器黑名单', style=wx.ALIGN_CENTER)
        policyGridSizer.Add(serverBlacklistTitle, pos=(0, 1), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        userBlacklistTitle = wx.StaticText(parent=self.policyPanel, id=-1, label='用户黑名单', style=wx.ALIGN_CENTER)
        policyGridSizer.Add(userBlacklistTitle, pos=(0, 2), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        fileBlacklistTitle = wx.StaticText(parent=self.policyPanel, id=-1, label='文件黑名单', style=wx.ALIGN_CENTER)
        policyGridSizer.Add(fileBlacklistTitle, pos=(0, 3), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        extensionBlacklistTitle = wx.StaticText(parent=self.policyPanel, id=-1, label='拓展名黑名单', style=wx.ALIGN_CENTER)
        policyGridSizer.Add(extensionBlacklistTitle, pos=(0, 4), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        pathBlacklistTitle = wx.StaticText(parent=self.policyPanel, id=-1, label='路径黑名单', style=wx.ALIGN_CENTER)
        policyGridSizer.Add(pathBlacklistTitle, pos=(0, 5), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        policyGridSizer.Add(self.clientBlacklist, pos=(1, 0), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        policyGridSizer.Add(self.serverBlacklist, pos=(1, 1), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        policyGridSizer.Add(self.userBlacklist, pos=(1, 2), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        policyGridSizer.Add(self.fileBlacklist, pos=(1, 3), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        policyGridSizer.Add(self.extensionBlacklist, pos=(1, 4), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        policyGridSizer.Add(self.pathBlacklist, pos=(1, 5), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        sizeLimitTitle = wx.StaticText(parent=self.policyPanel, id=-1, label='文件大小限制', style=wx.ALIGN_CENTER)
        policyGridSizer.Add(sizeLimitTitle, pos=(2, 0), span=(1, 1), flag=wx.ALIGN_CENTER, border=5)
        policyGridSizer.Add(self.sizeLimit, pos=(2, 1), span=(1, 2), flag=wx.EXPAND | wx.ALL, border=5)
        policyGridSizer.Add(self.retrPolicy, pos=(2, 3), span=(1, 1), flag=wx.ALIGN_CENTER, border=5)
        policyGridSizer.Add(self.storPolicy, pos=(2, 4), span=(1, 1), flag=wx.ALIGN_CENTER, border=5)
        policyGridSizer.Add(self.policyApply, pos=(2, 5), span=(1, 1), flag=wx.ALIGN_CENTER, border=5)
        policyGridSizer.AddGrowableRow(1)
        policyGridSizer.AddGrowableCol(0)
        policyGridSizer.AddGrowableCol(1)
        policyGridSizer.AddGrowableCol(2)
        policyGridSizer.AddGrowableCol(3)
        policyGridSizer.AddGrowableCol(4)
        policyGridSizer.AddGrowableCol(5)
        self.policyPanel.SetSizer(policyGridSizer)
        # Setup detail panel
        sessionDetailGridSizer = wx.GridBagSizer(0, 0)
        clientInfoTitle = wx.StaticText(parent=self.detailPanel, id=-1, label='客户端信息', style=wx.ALIGN_CENTER)
        sessionDetailGridSizer.Add(clientInfoTitle, pos=(0, 0), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        sessionDetailGridSizer.Add(self.clientInfo, pos=(0, 1), span=(1, 2), flag=wx.EXPAND | wx.ALL, border=5)
        serverInfoTitle = wx.StaticText(self.detailPanel, id=-1, label='服务器信息', style=wx.ALIGN_CENTER)
        sessionDetailGridSizer.Add(serverInfoTitle, pos=(1, 0), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        sessionDetailGridSizer.Add(self.serverInfo, pos=(1, 1), span=(1, 2), flag=wx.EXPAND | wx.ALL, border=5)
        sessionDetailGridSizer.AddGrowableCol(1)
        usernameTitle = wx.StaticText(parent=self.detailPanel, id=-1, label='用户名', style=wx.ALIGN_CENTER)
        sessionDetailGridSizer.Add(usernameTitle, pos=(0, 3), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        sessionDetailGridSizer.Add(self.username, pos=(0, 4), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        passwordTitle = wx.StaticText(parent=self.detailPanel, id=-1, label='密码', style=wx.ALIGN_CENTER)
        sessionDetailGridSizer.Add(passwordTitle, pos=(1, 3), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        sessionDetailGridSizer.Add(self.password, pos=(1, 4), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        sessionDetailGridSizer.AddGrowableCol(4)
        sessionDetailGridSizer.AddGrowableRow(0)
        sessionDetailGridSizer.AddGrowableRow(1)
        self.detailPanel.SetSizer(sessionDetailGridSizer)
        # Setup file downloading
        sessionFileGridSizer = wx.GridBagSizer(0, 0)
        sessionFileGridSizer.Add(self.selectFile, pos=(0, 0), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        sessionFileGridSizer.Add(self.extractFile, pos=(1, 0), span=(1, 1), flag=wx.EXPAND | wx.ALL, border=5)
        sessionFileGridSizer.AddGrowableCol(0)
        sessionFileGridSizer.AddGrowableRow(0)
        sessionFileGridSizer.AddGrowableRow(1)
        self.buttonPanel.SetSizer(sessionFileGridSizer)
        # Set policy
        self.policy = policyManager.reader()
        self.clientBlacklist.SetValue('\n'.join(self.policy['clientBlacklist']))
        self.serverBlacklist.SetValue('\n'.join(self.policy['serverBlacklist']))
        self.userBlacklist.SetValue('\n'.join(self.policy['userBlacklist']))
        self.fileBlacklist.SetValue('\n'.join(self.policy['fileBlacklist']))
        self.extensionBlacklist.SetValue('\n'.join(self.policy['extensionBlacklist']))
        self.pathBlacklist.SetValue('\n'.join(self.policy['pathBlacklist']))
        self.sizeLimit.SetValue(self.policy['sizeLimit'])
        self.retrPolicy.SetValue(self.policy['retrPolicy'])
        self.storPolicy.SetValue(self.policy['storPolicy'])

    def onRefresh(self, evt):
        # Called when main window click refresh button
        self.sessions = []
        fileList = ['./record/'+x for x in os.listdir('./record/')]
        for i in fileList:
            self.sessions.append(ftcap.reader(i))
        # Reload session list
        self.sessionList.Clear()
        for i in self.sessions:
            self.sessionList.Append(i[0].info.time.ctime())
        #Select first item in session list
        self.sessionList.SetSelection(0)
        self._selectSessionList(0)

    def onSelect(self, evt):
        # Called when main window click item in session list
        selection = self.sessionList.GetSelection()
        self._selectSessionList(selection)

    def _selectSessionList(self, selection):
        # Select selection+1 item in session list
        self.flowList.DeleteAllItems()
        print(str(self.sessions[selection][0].info.client), str(self.sessions[selection][0].info.server))
        self.clientInfo.SetLabel(str(self.sessions[selection][0].info.client))
        self.serverInfo.SetLabel(str(self.sessions[selection][0].info.server))
        username = ''
        password = ''
        self.files = {}
        fileTransferring = False
        fileName = ''
        fileContent = ''
        for i in self.sessions[selection][1]:
            recvData = str(i.info.ftp.raw if 'ftp' in i else i.info.raw.packet)[2:-1]
            self.flowList.Append((i.info.time.ctime(), i.info.src.ip, i.info.src.port,
                                  i.info.dst.ip, i.info.dst.port, recvData))
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

    def onApply(self, evt):
        value = self.serverBlacklist.GetValue()
        blacklist = []
        for i in value.split('\n'):
            blacklist.append(i)
        with open('serverBlacklist.json', 'w') as f:
            json.dump(blacklist, f)


class Firewall(wx.App):
    def OnInit(self):
        self.frame = mainFrame(parent=None, id=-1, title="Transparent Proxy Manager")
        self.frame.Show()
        self.frame.Centre()
        self.SetTopWindow(self.frame)
        return True


if __name__ == '__main__':
    app = Firewall()
    app.MainLoop()
