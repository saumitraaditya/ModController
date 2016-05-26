#!/usr/bin/env python
import thread
import json
from controller.framework.ControllerModule import ControllerModule
import controller.framework.fxlib as fxlib
import sleekxmpp
from collections import defaultdict
from sleekxmpp.xmlstream.stanzabase import ElementBase, ET, JID
from sleekxmpp.xmlstream import register_stanza_plugin
from sleekxmpp.xmlstream.handler.callback import Callback
from sleekxmpp.xmlstream.matcher import StanzaPath
from sleekxmpp.stanza.message import Message
from sleekxmpp.plugins.base import base_plugin


#set up a new custom message stanza
class Ipop_Msg(ElementBase):
    namespace = 'Conn_setup'
    name = 'Ipop'
    plugin_attrib = 'Ipop'
    interfaces = set(('setup','payload','uid'))
    subinterfaces = interfaces



class XmppClient(ControllerModule,sleekxmpp.ClientXMPP):
    def __init__(self,CFxHandle,paramDict,ModuleName):
        ControllerModule.__init__(self,CFxHandle,paramDict,ModuleName)
        self.xmpp_peers = defaultdict(int)
        # need to maintain uid<->jid mapping to route xmpp messages.
        self.uid_jid = {}
        self.xmpp_username = self.CMConfig.get("username")
        self.xmpp_passwd = self.CMConfig.get("password")
        self.xmpp_host = self.CMConfig.get("xmpp_host")
        self.uid = ""
        # initialize the base Xmpp client class
        sleekxmpp.ClientXMPP.__init__(self,self.xmpp_username,self.xmpp_passwd)
        # register a new plugin stanza and handler for it,
        # whenever a matching message will be received on 
        # the xmpp stream , registered handler will be called.
        register_stanza_plugin(Message, Ipop_Msg)
        self.registerHandler(
                Callback('Ipop',
                StanzaPath('message/Ipop'),
                self.MsgListener))
        # Register event handler for session start 
        self.add_event_handler("session_start",self.start)
        # calculate UID, for the meantime
        # address mapping
        self.uid_ip4_table = {}
        self.ip4_uid_table = {}
        # populate uid_ip4_table and ip4_uid_table with all UID and IPv4
        # mappings within the /16 subnet
        parts = self.CMConfig["ip4"].split(".")
        ip_prefix = parts[0] + "." + parts[1] + "."
        for i in range(0, 255):
            for j in range(0, 255):
                ip4 = ip_prefix + str(i) + "." + str(j)
                uid = fxlib.gen_uid(ip4)
                self.uid_ip4_table[uid] = ip4
                self.ip4_uid_table[ip4] = uid
        self.uid = self.ip4_uid_table[self.CMConfig["ip4"]]
        # Start xmpp handling thread
        self.xmpp_handler()
        
    # Triggered at start of XMPP session
    def start(self,event):
        self.get_roster()
        self.send_presence()
        # Add handler for incoming presence messages.
        self.add_event_handler("presence_available",self.handle_presence)
        
    # will need to handle presence, to keep track of who is online.    
    def handle_presence(self,presence):
        presence_sender = presence['from']
        if (self.xmpp_peers[presence_sender]==0):
            self.xmpp_peers[presence_sender]=1
            self.log("presence received from {0}".format(presence_sender))
        
        
    # This handler method listens for the matched messages on tehj xmpp stream, 
    # extracts the setup and payload and takes suitable action depending on the 
    # them.
    def MsgListener(self,msg):
        # extract setup and content
        setup = str(msg['Ipop']['setup'])
        payload = str(msg['Ipop']['payload'])
        msg_type,target_uid,target_jid = setup.split("#")
        
        if (msg_type == "regular_msg"):
                self.log("Recvd mesage from {0}".format(msg['from']))
                self.log("Msg is {0}".format(payload))
        elif (msg_type == "xmpp_advertisement"):
            peer_uid = payload
            if (peer_uid != self.uid):
                self.uid_jid[peer_uid]=msg['from']
                msg = {}
                msg["uid"] = peer_uid
                msg["data"] = payload
                msg["type"] = "xmpp_advertisement"
                self.registerCBT('BaseTopologyManager','XMPP_MSG',msg)
                self.log("recvd xmpp_advt from {0}".format(msg["uid"]))
        # compare uid's here , if target uid does not match with mine do nothing.
        # have to avoid loop messages.
        if (target_uid == self.uid):
            if (msg_type == "con_req"):
                sender_uid,recvd_data = payload.split("#")
                msg = {}
                msg["uid"] = sender_uid
                msg["data"] = recvd_data
                msg["type"] = "con_req"
                # send this CBT to BaseTopology Manager
                self.registerCBT('BaseTopologyManager','XMPP_MSG',msg)
                self.log("recvd con_req from {0}".format(msg["uid"]))
                
            elif (msg_type == "con_resp"):
                sender_uid,recvd_data = payload.split("#")
                msg = {}
                msg["uid"] = sender_uid
                msg["data"] = recvd_data
                msg["type"] = "peer_con_resp"
                self.registerCBT('BaseTopologyManager','XMPP_MSG',msg)
                self.log("recvd con_resp from {0}".format(msg["uid"]))
                
            elif (msg_type == "con_ack"):
                sender_uid,recvd_data = payload.split("#")
                msg = {}
                msg["uid"] = sender_uid
                msg["data"] = recvd_data
                msg["type"] = "con_ack"
                self.registerCBT('BaseTopologyManager','XMPP_MSG',msg)
                self.log("recvd con_ack from {0}".format(msg["uid"]))
                
            elif (msg_type == "ping_resp"):
                sender_uid,recvd_data = payload.split("#")
                msg = {}
                msg["uid"] = sender_uid
                msg["data"] = recvd_data
                msg["type"] = "ping_resp"
                self.registerCBT('BaseTopologyManager','XMPP_MSG',msg)
                self.log("recvd ping_resp from {0}".format(msg["uid"]))
                
            elif (msg_type == "ping"):
                sender_uid,recvd_data = payload.split("#")
                msg = {}
                msg["uid"] = sender_uid
                msg["data"] = recvd_data
                msg["type"] = "ping"
                self.registerCBT('BaseTopologyManager','XMPP_MSG',msg)
                self.log("recvd ping from {0}".format(msg["uid"]))
                
            
    def sendMsg(self,peer_jid,setup_load=None,msg_payload=None):
        if (setup_load == None):
            setup_load = unicode("regular_msg" + "#" + "None" + "#" + peer_jid.full)
        else:
            setup_load = unicode(setup_load + "#" + peer_jid.full)
       
        if (msg_payload==None):
            content_load = "Hello there this is {0}".format(self.xmpp_username)
        else:
            content_load = msg_payload
           
        msg = self.Message()
        msg['to'] = peer_jid
        msg['type'] = 'chat'
        msg['Ipop']['setup'] = setup_load
        msg['Ipop']['payload'] = content_load
        msg.send()
        self.log("Sent a message to  {0}".format(peer_jid))
        
    def xmpp_handler(self):
        try:
            if (self.connect(address = (self.xmpp_host,5222))):
                thread.start_new_thread(self.process,())
        except:
            self.log("Unable to start XMPP handling thread.",severity='error')
            
    def log(self,msg,severity='info'):
        self.registerCBT('Logger',severity,msg)
        
    def initialize(self):
        self.log("{0} module Loaded".format(self.ModuleName))
        
    def processCBT(self, cbt):
        if (cbt.action == "DO_SEND_MSG"):
            method  = cbt.data.get("method")
            peer_uid = cbt.data.get("uid")
            peer_jid = self.uid_jid[peer_uid]
            data = cbt.data.get("data")
            if (method == "con_req"):
                setup_load = "con_req"+"#"+peer_uid
                msg_payload = self.uid+"#"+data
                self.sendMsg(peer_jid,setup_load,msg_payload)
                self.log("sent con_req to {0}".format(self.uid_jid[peer_uid]))
            elif (method == "con_resp"):
                setup_load = "con_resp"+"#"+peer_uid
                msg_payload = self.uid+"#"+data
                self.sendMsg(peer_jid,setup_load,msg_payload)
                self.log("sent con_resp to {0}".format(self.uid_jid[peer_uid]))
            elif (method == "con_ack"):
                setup_load = "con_ack"+"#"+peer_uid
                msg_payload = self.uid+"#"+data
                self.sendMsg(peer_jid,setup_load,msg_payload)
                self.log("sent con_ack to {0}".format(self.uid_jid[peer_uid]))
            elif (method == "ping_resp"):
                setup_load = "ping_resp"+"#"+peer_uid
                msg_payload = self.uid+"#"+data
                self.sendMsg(peer_jid,setup_load,msg_payload)
                self.log("sent ping_resp to {0}".format(self.uid_jid[peer_uid]))
            elif (method == "ping"):
                setup_load = "ping"+"#"+peer_uid
                msg_payload = self.uid+"#"+data
                self.sendMsg(peer_jid,setup_load,msg_payload)
                self.log("sent ping to {0}".format(self.uid_jid[peer_uid]))
        
    def timer_method(self):
        try:
            for peer in self.xmpp_peers.keys():
                if (self.uid != ""):
                    setup_load = "xmpp_advertisement"+"#"+"None"
                    msg_load = str(self.uid)
                    self.sendMsg(peer,setup_load,msg_load)
                    self.log("sent xmpp_advt to {0}".format(peer))
        except:
            self.log("Exception in XmppClient timer")
            
    def terminate(self):
        pass


