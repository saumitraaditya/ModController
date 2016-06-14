#!/usr/bin/env python
import thread
import json
import time
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
        self.jid_uid = defaultdict(lambda:['',False])
        self.xmpp_username = self.CMConfig.get("xmpp_username")
        self.xmpp_passwd = self.CMConfig.get("xmpp_password")
        self.xmpp_host = self.CMConfig.get("xmpp_host")
        self.xmpp_port = self.CMConfig.get("xmpp_port")
        self.uid = ""
        # time of last recvd xmpp advt.
        self.last_sent_advt = 0
        # keeps track of if xmpp advt recvd in interval
        self.xmpp_advt_recvd = True
        # Initial ADVT Delay
        self.INITIAL_ADVT_DELAY =5
        # interval between sending advertisements
        self.advt_delay = self.INITIAL_ADVT_DELAY
        # Maximum delay between advertisements is 10 minutes
        self.MAX_ADVT_DELAY = 600 
        # initialize the base Xmpp client class
        sleekxmpp.ClientXMPP.__init__(self,self.xmpp_username,self.xmpp_passwd,sasl_mech='PLAIN')
        self['feature_mechanisms'].unencrypted_plain = True
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
        parts = self.CFxHandle.queryParam("ip4").split(".")
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
        sender_jid = msg['from']
        
        if (msg_type == "regular_msg"):
                self.log("Recvd mesage from {0}".format(msg['from']))
                self.log("Msg is {0}".format(payload))
        elif (msg_type == "xmpp_advertisement"):
            # peer_uid - uid of the node that sent the advt
            # target_uid - what it percieves as my uid
            try:
                peer_uid,target_uid = payload.split("#")
                if (peer_uid != self.uid):
                    self.uid_jid[peer_uid] = sender_jid
                    self.jid_uid[msg['from']][0] = peer_uid
                    # sender knows my uid, so I will not send an advert to him
                    if (target_uid == self.uid):
                        self.jid_uid[msg['from']][1] = True
                    else:
                       self.jid_uid[msg['from']][1] = False 
                    msg = {}
                    msg["uid"] = peer_uid
                    msg["data"] = peer_uid
                    msg["type"] = "xmpp_advertisement"
                    self.registerCBT('BaseTopologyManager','XMPP_MSG',msg)
                    # refresh xmpp advt recvd flag
                    self.xmpp_advt_recvd = True
                    self.log("recvd xmpp_advt from {0}".format(msg["uid"]))
            except:
                self.log("advt_payload: {0}".format(payload))
                
        # compare uid's here , if target uid does not match with mine do nothing.
        # have to avoid loop messages.
        if (target_uid == self.uid):
            sender_uid,recvd_data = payload.split("#")
            # If I recvd XMPP msg from this peer, I should record his UID-JID
            self.uid_jid[sender_uid] = sender_jid
            if (msg_type == "con_req"):
                msg = {}
                msg["uid"] = sender_uid
                msg["data"] = recvd_data
                msg["type"] = "con_req"
                # send this CBT to BaseTopology Manager
                self.registerCBT('BaseTopologyManager','XMPP_MSG',msg)
                self.log("recvd con_req from {0}".format(msg["uid"]))
                
            elif (msg_type == "con_resp"):
                msg = {}
                msg["uid"] = sender_uid
                msg["data"] = recvd_data
                msg["type"] = "peer_con_resp"
                self.registerCBT('BaseTopologyManager','XMPP_MSG',msg)
                self.log("recvd con_resp from {0}".format(msg["uid"]))
                
            elif (msg_type == "con_ack"):
                msg = {}
                msg["uid"] = sender_uid
                msg["data"] = recvd_data
                msg["type"] = "con_ack"
                self.registerCBT('BaseTopologyManager','XMPP_MSG',msg)
                self.log("recvd con_ack from {0}".format(msg["uid"]))
                
            elif (msg_type == "ping_resp"):
                msg = {}
                msg["uid"] = sender_uid
                msg["data"] = recvd_data
                msg["type"] = "ping_resp"
                self.registerCBT('BaseTopologyManager','XMPP_MSG',msg)
                self.log("recvd ping_resp from {0}".format(msg["uid"]))
                
            elif (msg_type == "ping"):
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
        msg['to'] = peer_jid.bare
        msg['type'] = 'chat'
        msg['Ipop']['setup'] = setup_load
        msg['Ipop']['payload'] = content_load
        msg.send()
        self.log("Sent a message to  {0}".format(peer_jid))
        
    def xmpp_handler(self):
        try:
            if (self.connect(address = (self.xmpp_host,self.xmpp_port))):
                thread.start_new_thread(self.process,())
                self.log("Started XMPP handling")
                
        except:
            self.log("Unable to start XMPP handling thread-Check Internet connectivity/credentials.",severity='error')
            
    def log(self,msg,severity='info'):
        self.registerCBT('Logger',severity,msg)
        
    def initialize(self):
        self.log("{0} module Loaded".format(self.ModuleName))
        
    def processCBT(self, cbt):
        if (cbt.action == "DO_SEND_MSG"):
            method  = cbt.data.get("method")
            peer_uid = cbt.data.get("uid")
            try:
                peer_jid = self.uid_jid[peer_uid]
            except:
                log_msg = "UID-JID mapping for UID: {0} not present.\
                            msg: {1} will not be sent.".format(peer_uid,method)
                self.log(log_msg)
                return
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
                
    def sendXmppAdvt(self):
        if (self.uid != ""):
            for peer in self.xmpp_peers.keys():
                if (self.jid_uid[peer][1] == False):
                    setup_load = "xmpp_advertisement"+"#"+"None"
                    msg_load = str(self.uid) + "#" + str(self.jid_uid[peer][0])
                    self.sendMsg(peer,setup_load,msg_load)
                    self.log("sent xmpp_advt to {0}".format(peer))
        
    def timer_method(self):
        try:
            if (time.time() - self.last_sent_advt > self.advt_delay):
                # see if I recvd a advertisement in this time period
                # if yes than XMPP link is open
                if (self.xmpp_advt_recvd == True):
                    self.sendXmppAdvt()
                    # update xmpp tracking parameters.
                    self.last_sent_advt = time.time()
                    self.xmpp_advt_recvd = False
                    self.advt_delay = self.INITIAL_ADVT_DELAY
                # Have not heard from anyone in a while
                elif (self.advt_delay < self.MAX_ADVT_DELAY):
                        self.advt_delay = 2 * self.advt_delay
                        self.log("Delaying the XMPP advt timer \
                            to {0} seconds".format(self.advt_delay))
                else:
                    # send the advertisement anyway.
                    self.sendXmppAdvt()
                    # update xmpp tracking parameters.
                    self.last_sent_advt = time.time()
                    self.xmpp_advt_recvd = False
                            
        except:
            self.log("Exception in XmppClient timer")
            
    def terminate(self):
        pass


