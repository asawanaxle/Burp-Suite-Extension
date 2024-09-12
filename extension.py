from burp import ITab
from burp import IBurpExtender
from burp import IHttpListener
from burp import IContextMenuFactory
from burp import IParameter
from burp import IExtensionHelpers
from burp import IRequestInfo
from burp import IMessageEditorController
from burp import IHttpRequestResponse
from burp import IHttpRequestResponseWithMarkers
from burp import IHttpService
from burp import ITextEditor
from javax.swing import JList
from javax.swing import JTable
from java.awt import Dimension
from javax.swing import JButton
from javax.swing import DefaultListModel
from javax.swing import JFrame
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import JToggleButton
from javax.swing import JCheckBox
from javax.swing import DefaultComboBoxModel
from javax.swing import JMenuItem
from javax.swing import JTextArea
from javax.swing import JTree
from javax.swing import JFileChooser
from javax.swing import JOptionPane
from javax.swing import JComboBox
from javax.swing import BorderFactory
from javax.swing.border import Border
from javax.swing.table import AbstractTableModel
from java.awt.event import ActionListener
from javax.swing.tree import TreePath
from java.util import LinkedList
from javax.swing import JPopupMenu
from javax.swing import JSplitPane
from javax.swing import JEditorPane
from javax.swing import JScrollPane
from javax.swing import JTabbedPane
from javax.swing import SwingUtilities
from java.awt import BorderLayout
from java.awt import GridLayout
from java.awt import Color
from java.lang import Runnable
from threading import Lock
from java.util import ArrayList
from java.lang import Integer
from java.lang import String
import re
import os
import subprocess
from subprocess import Popen, PIPE
from subprocess import PIPE



class BurpExtender(IBurpExtender,ITab, IMessageEditorController, AbstractTableModel, IContextMenuFactory, IHttpRequestResponseWithMarkers, ITextEditor,ActionListener):

    def registerExtenderCallbacks(self,callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Extension 2")
        self._log = ArrayList()
        self._originalCurlArray = ArrayList()
        self._modifiedCurlArray = ArrayList()
        self._originalResponseArray = ArrayList()
        self._modifiedResponseArray = ArrayList()
        self._lock = Lock()
        self.headers = ["Cookies","URL"]
        self.payloads = ["#","$"]
        self.selectedHeaders = ArrayList()
        self.selectedPayloads = ArrayList()
        print("Welcome to Extension 2!")
        self.ui()

        callbacks.customizeUiComponent(self._splitPane)
        # callbacks.customizeUiComponent(self.importButton)
        callbacks.customizeUiComponent(self.logTable)
        # callbacks.customizeUiComponent(self.panel)
        # callbacks.customizeUiComponent(self.scrollPane)

        self._callbacks.addSuiteTab(self)
        return

    # creating the UI
    def ui(self):
        self._splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._splitPane.setDividerLocation(400)
        self.mainPanel = JPanel(BorderLayout())

        self.innerPanel1 = JPanel()
        self.innerPanel1.setBorder(BorderFactory.createLineBorder(Color.black))
        self.importButton = JButton("Import Curl File")
        self.importButton.setBounds(0,0,30,100)
        self.importButton.addActionListener(self)
        self.innerPanel1.add(self.importButton)
        self.mainPanel.add(self.innerPanel1,BorderLayout.WEST)

        self.innerPanel2 = JPanel()
        self.innerPanel2.setBorder(BorderFactory.createLineBorder(Color.black))
        self.logTable = Table(self)
        self.scrollPane = JScrollPane(self.logTable)
        self.innerPanel2.setLayout(None)
        self.scrollPane.setBounds(10,10,1000,200)
        self.innerPanel2.add(self.scrollPane)
        self.label = JLabel("Select the required headers")
        self.label.setBounds(10,200,500,50)
        self.innerPanel2.add(self.label)

        self.comboBox = JComboBox(self.headers)
        self.comboBox.setBounds(10,250,100,20)
        self.comboBox.addActionListener(ComboBoxActionListener(self))
        self.innerPanel2.add(self.comboBox)

        self.jlist = JList()
        self.scrollPaneJlist = JScrollPane(self.jlist)
        self.scrollPaneJlist.setBounds(10,280,300,100)
        self.scrollPaneJlist.setBorder(BorderFactory.createLineBorder(Color.black))
        self.innerPanel2.add(self.scrollPaneJlist)

        self.addButton = JButton("Add Custom Header")
        self.addButton.setBounds(120,250,150,20)
        self.addButton.addActionListener(self.addHeader)
        self.innerPanel2.add(self.addButton)

        self.delButton = JButton("Delete Header")
        self.delButton.setBounds(280,250,110,20)
        self.delButton.addActionListener(self.delHeader)
        self.innerPanel2.add(self.delButton)

        self.label2 = JLabel("Select the required payloads")
        self.label2.setBounds(500,200,500,50)
        self.innerPanel2.add(self.label2)

        self.comboBox2 = JComboBox(self.payloads)
        self.comboBox2.setBounds(500,250,100,20)
        self.comboBox2.addActionListener(ComboBox2ActionListener(self))
        self.innerPanel2.add(self.comboBox2)

        self.jlist2 = JList()
        self.scrollPaneJlist2 = JScrollPane(self.jlist2)
        self.scrollPaneJlist2.setBounds(500,280,300,100)
        self.scrollPaneJlist2.setBorder(BorderFactory.createLineBorder(Color.black))
        self.innerPanel2.add(self.scrollPaneJlist2)

        self.addButton2 = JButton("Add Custom Payload")
        self.addButton2.setBounds(610,250,150,20)
        self.addButton2.addActionListener(self.addPayload)
        self.innerPanel2.add(self.addButton2)

        self.delButton2 = JButton("Delete Payload")
        self.delButton2.setBounds(770,250,110,20)
        self.delButton2.addActionListener(self.delPayload)
        self.innerPanel2.add(self.delButton2)

        self.launchButton = JButton("Launch Attack")
        self.launchButton.setBounds(10,400,200,40)
        self.launchButton.addActionListener(self.attackLauncher)
        self.innerPanel2.add(self.launchButton)

        self.mainPanel.add(self.innerPanel2,BorderLayout.CENTER)
        # self.label = JLabel()
        # self.panel.add(self.label)
        
        self._splitPane.setLeftComponent(self.mainPanel)
        tabs = JTabbedPane()
        self._originalCurlViewer = self._callbacks.createMessageEditor(self, False)
        self._modifiedCurlViewer = self._callbacks.createMessageEditor(self, False)
        self._originalResponseViewer = self._callbacks.createMessageEditor(self, False)
        self._modifiedResponseViewer = self._callbacks.createMessageEditor(self, False)
        tabs.addTab("Original Curl", self._originalCurlViewer.getComponent())
        tabs.addTab("Modified Curl", self._modifiedCurlViewer.getComponent())
        tabs.addTab("Original Response", self._originalResponseViewer.getComponent())
        tabs.addTab("Modified Response", self._modifiedResponseViewer.getComponent())
        self._splitPane.setRightComponent(tabs)

    # implement ITab
    def getTabCaption(self):
        return "Extension2"

    def getUiComponent(self):
        return self._splitPane

    # implement abstract table model
    def getRowCount(self):
        try:
                return self._log.size()
        except:
                return 0

    def getColumnCount(self):
        return 2

    def getColumnName(self,columnIndex):
        data = ['#','CURL']
        try:
            return data[columnIndex]
        except IndexError:
            return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return rowIndex+1
        if columnIndex == 1:
            return logEntry._originalCurlArray
        return ""

    def getColumnClass(self,columnIndex):
        data = [Integer, String]
        try:
            return data[columnIndex]
        except IndexError:
            return ""

   # Implement IMessageEditorController methods
    def getHttpService(self):
       return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
       return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
       return self._currentlyDisplayedItem.getResponse()

    def actionPerformed(self, e):
        fc = JFileChooser()
        i = fc.showOpenDialog(None)
        if i==JFileChooser.APPROVE_OPTION :
            f=fc.getSelectedFile()
            filepath=f.getPath()
            f = open(filepath, "r")
            s = ""
            res = ""

            while(1):
                s = f.readline()
                if not s:
                    break
                if s.find("###")!=-1:
                    self.addToLog(res)
                    self._originalCurlArray.add(res)
                    res=""
                else:
                    res = res+s
            # print(curls)
            # self.addToLog(curls)
            # print(self._curlArray)

    def testCode(self,res):
        print("Response:")
        f1= open("temp_req.txt","w")
        f1.write(res)
        f1.close()
    	cmd = 'bash temp_req.txt'
        response = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True)
    	# print(subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True))
        return response
        
        
    def addToLog(self, curl):
        self._lock.acquire()
        row = self._log.size()
        self._log.add(LogEntry(curl))
        SwingUtilities.invokeLater(UpdateTableEDT(self,"insert",row,row))
        self._lock.release()

    def addHeader(self,e):
        temp = JOptionPane.showInputDialog("Please provide header title")
        self.selectedHeaders.add(temp)
        self.jlist.setListData(self.selectedHeaders)

    def addPayload(self,e):
        temp = JOptionPane.showInputDialog("Please provide payload")
        self.selectedPayloads.add(temp)
        self.jlist2.setListData(self.selectedPayloads)

    def delHeader(self,e):
        self.selectedHeaders.remove(self.jlist.getSelectedValue())
        self.jlist.setListData(self.selectedHeaders)

    def delPayload(self,e):
        self.selectedPayloads.remove(self.jlist2.getSelectedValue())
        self.jlist2.setListData(self.selectedPayloads)

    def attackLauncher(self,e):
        for p in self.selectedPayloads:
            # i=1
            file = open("Output.txt",'a+')
            file.write("Payload :")
            file.write(p)
            file.write("\n")
            file.close()
            print(p)
            for c in self._originalCurlArray:
                originalResponse = self.testCode(c)
                self._originalResponseArray.add(originalResponse)
                # print(i)
                # i+=1
                x = re.search("-b ", c)
                if(x==None):
                    continue
                counter = x.end()
                counter+=1
                temp = ''
                while(c[counter]!='\''):
                    temp = temp+c[counter]
                    counter+=1
                # print(temp)
                if(temp==''):
                    c=c[:x.end()+1] + p + c[x.end()+1:]
                else:
                    c = c.replace(temp, p)

                print(c)
                self._modifiedCurlArray.add(c)
                response = self.testCode(c)
                self._modifiedResponseArray.add(response)

    # def attackLauncher(self,e):
    #     print("Response:")
    #     for c in self._curlArray:
    #         print(c)
    #         self.testCode(c)
            


class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)

    def changeSelection(self, row, col, toggle, extend):
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        print(logEntry)
        print(row)
        # self.temp = logEntry._payload
        self._extender._originalCurlViewer.setMessage(logEntry._originalCurlArray, True)
        self._extender._modifiedCurlViewer.setMessage(self._extender._modifiedCurlArray[row], True)
        self._extender._originalResponseViewer.setMessage(self._extender._originalResponseArray[row], True)
        self._extender._modifiedResponseViewer.setMessage(self._extender._modifiedResponseArray[row], True)
        JTable.changeSelection(self, row, col, toggle, extend)

class LogEntry():
    def __init__(self,_originalCurlArray):
        self._originalCurlArray = _originalCurlArray
        return

class UpdateTableEDT(Runnable):
    def __init__(self,extender,action,firstRow,lastRow):
        self._extender=extender
        self._action=action
        self._firstRow=firstRow
        self._lastRow=lastRow

    def run(self):
        if self._action == "insert":
            self._extender.fireTableRowsInserted(self._firstRow, self._lastRow)
        elif self._action == "update":
            self._extender.fireTableRowsUpdated(self._firstRow, self._lastRow)
        elif self._action == "delete":
            self._extender.fireTableRowsDeleted(self._firstRow, self._lastRow)
        else:
            print("Invalid action in UpdateTableEDT")

class ComboBoxActionListener(ActionListener):
    def __init__(self,extender):
        self.extender = extender

    def actionPerformed(self,e):
        # print(self.extender.comboBox.getSelectedItem())
        # self.extender.textArea.append(self.extender.comboBox.getSelectedItem())
        self.extender.selectedHeaders.add(self.extender.comboBox.getSelectedItem())
        # print(self.extender.selectedHeaders)
        self.extender.jlist.setListData(self.extender.selectedHeaders)


class ComboBox2ActionListener(ActionListener):
    def __init__(self,extender):
        self.extender = extender

    def actionPerformed(self,e):
        # print(self.extender.comboBox.getSelectedItem())
        # self.extender.textArea.append(self.extender.comboBox.getSelectedItem())
        self.extender.selectedPayloads.add(self.extender.comboBox2.getSelectedItem())
        # print(self.extender.selectedPayloads)
        self.extender.jlist2.setListData(self.extender.selectedPayloads)

