# -*- coding: utf-8 -*-
#
# Copyright 2014 Orange
# Copyright 2015 Rackspace Hosting
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import itertools

from bagpipe.bgp.common import logDecorator

from bagpipe.bgp.common.run_command import runCommand

from bagpipe.bgp.common.looking_glass import LookingGlassLocalLogger

from bagpipe.bgp.vpn.evpn import VPNInstanceDataplane
from bagpipe.bgp.vpn.dataplane_drivers import DataplaneDriver

from bagpipe.exabgp.message.update.attribute.communities import Encapsulation

OVS_REMOTE_TABLE = 100
OVS_TUNNEL_REG = 0
OVS_TUNNEL_PORT = 'tun-vxlan'

ARP_FLOW = ('table=%(table)s',
            'arp',
            'reg=%(instance_id)s',
            'nw_dst=%(ip)s',
            'actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[]',
            'mod_dl_src:%(mac)s',
            'load:0x2->NXM_OF_ARP_OP[]',
            'move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[]',
            'move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[]',
            'load:%(mac)s->NXM_NX_ARP_SHA[]',
            'load:%(ip)s->NXM_OF_ARP_SPA[],in_port')
ARP_FLOW = ','.join(ARP_FLOW)

REMOTE_FLOW = ('table=%(table)d',
               'ip',
               'reg=%(instance_id)d',
               'dl_dst=%(mac)s',
               'nw_dst=%(ip)s',
               'actions=set_tunnel:%(vni)d',
               'set_field:%(remote_pe)s->tun_dst',
               #'set_field:%(local_pe)s->tun_src',
               'output:%(tunnel_ofport)d')
REMOTE_FLOW = ','.join(REMOTE_FLOW)

MULTICAST_FLOW_MATCH = ('table=%(table)d',
                        'ip',
                        'reg=%(instance_id)d',
                        'dl_dst=01:00:00:00:00:00/01:00:00:00:00:00')
MULTICAST_FLOW_MATCH = ','.join(MULTICAST_FLOW_MATCH)

MULTICAST_FLOW_ACTION = ('set_tunnel:%(vni)d',
                         'set_field:%(remote_pe)s->tun_dst',
                         #'set_field:%(local_pe)s->tun_src',
                         'output:%(tunnel_ofport)d')
MULTICAST_FLOW_ACTION = ','.join(MULTICAST_FLOW_ACTION)


class OvsVXLANEVIDataplane(VPNInstanceDataplane):

    def __init__(self, *args, **kwargs):
        VPNInstanceDataplane.__init__(self, *args)

        self.bridge = self.driver.bridge
        self._multicast = {}

        self.log.debug('Creating tunnel flow port')
        flow_port_args = {'bridge': self.bridge, 'port': OVS_TUNNEL_PORT}

        cmd = ('ovs-vsctl --may-exist add_port %(bridge)s'
               '%(port)s -- set interface %(port)s type=vxlan'
               'options:remote_ip=flow options:key=flow')
        self._runCommand(cmd % flow_port_args)

        cmd = 'ovs-vsctl get Interface %(port)s ofport'
        (self.tunnel_ofport, ) = self._runCommand(cmd % flow_port_args)

    def _add_flows(self, *flows, **format_args):
        # TODO(jkoelker) batch flows for atomic flushing
        format_args = self._get_flow_format_args(**format_args)

        for flow in flows:
            flow = 'cookie=%(instance_id)d,' + flow
            cmd = 'ovs-ofctl del-flows %(bridge)s ' + flow
            self._runCommand(cmd % format_args)

    def _del_flows(self, *flows, **format_args):
        # TODO(jkoelker) batch flows for atomic flushing
        format_args = self._get_flow_format_args(**format_args)

        for flow in flows:
            # NOTE(jkoelker) get rid of everything except the match
            action_pos = flow.find('action')

            if action_pos != -1:
                flow = flow[:action_pos].strip(',')

            flow = 'cookie=%(instance_id)d/-1,' + flow
            cmd = 'ovs-ofctl add-flow %(bridge)s ' + flow
            self._runCommand(cmd % format_args)

    def _get_flow_format_args(self, **format_args):
        format_args['instance_id'] = self.instanceId
        format_args['tunnel_ofport'] = self.tunnel_ofport
        format_args['brige'] = self.bridge

        return format_args

    def _add_multicast(self, vni, remote_pe=None, of_port=None):
        self._multicast[(vni, remote_pe, of_port)] = None

    def _del_multicast(self, vni, remote_pe=None, of_port=None):
        self._multicast.pop((vni, remote_pe, of_port), None)

    def _flush_multicast(self):
        if not self._multicast:
            self._del_flows(MULTICAST_FLOW_MATCH, table=OVS_REMOTE_TABLE)
            return

        local_actions = []
        remote_actions = []

        for vni, remote_pe, of_port in self.multicast.iterkeys():
            if remote_pe:
                format_args = {'vni': vni, 'remote_pe': remote_pe}
                remote_actions.append(MULTICAST_FLOW_ACTION % format_args)

            elif of_port:
                local_actions.append('output:%s' % of_port)

        actions = itertools.chain(local_actions, remote_actions)
        actions = 'actions=' + ','.join(actions)

        flow = ','.join((MULTICAST_FLOW_MATCH, actions))

        self._add_flows(flow, table=OVS_REMOTE_TABLE)

    def setGatewayPort(self, linuxif):
        pass

    def gatewayPortDown(self, linuxif):
        pass

    @logDecorator.logInfo
    def vifPlugged(self, macAddress, ipAddress, localPort, label):
        cmd = 'ovs-vsctl get Interface %(port)s ofport'
        (self.tunnel_ofport, ) = self._runCommand(cmd % flow_port_args)
        self._add_multicast(self.instance_id, of_port
        pass

    @logDecorator.logInfo
    def vifUnplugged(self, macAddress, ipAddress, localPort, label,
                     lastEndpoint=True):
        pass

    @logDecorator.log
    def setupDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri,
                                        encaps):
        self._add_flows(REMOTE_FLOW, ARP_FLOW, mac=prefix, ip=nlri.ip,
                        vni=nlri.etag, remote_pe=remotePE,
                        table=OVS_REMOTE_TABLE)

    @logDecorator.log
    def removeDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri):
        self._del_flows(REMOTE_FLOW, ARP_FLOW, mac=prefix, ip=nlri.ip,
                        vni=nlri.etag, remote_pe=remotePE,
                        table=OVS_REMOTE_TABLE)

    @logDecorator.log
    def addDataplaneForBroadcastEndpoint(self, remotePE, label, nlri, encaps):
        self._add_multicast(vni=nlri.etag, remote_pe=remotePE)
        self._flush_multicast()

    @logDecorator.log
    def removeDataplaneForBroadcastEndpoint(self, remotePE, label, nlri):
        self._del_multicast(vni=nlri.etag, remote_pe=remotePE)
        self._flush_multicast()

    # Looking glass ####

    def getLookingGlassLocalInfo(self, pathPrefix):
        return {
            "ovs_bridge": self.bridge,
            "vxlan_if": self.vxlan_if_name
        }


class OvsVXLANDataplaneDriver(DataplaneDriver):

    """
    E-VPN Dataplane driver relying on the Linux kernel linuxbridge
    VXLAN implementation.
    """

    dataplaneInstanceClass = OvsVXLANEVIDataplane
    encaps = [Encapsulation(Encapsulation.VXLAN)]

    def __init__(self, config, init=True):
        LookingGlassLocalLogger.__init__(self, __name__)

        self.log.info("Initializing %s", self.__class__.__name__)

        DataplaneDriver.__init__(self, config, init)

    def _initReal(self, config):
        self.config = config
        self.log.info("Really initializing %s", self.__class__.__name__)

    def resetState(self):
        self.log.debug("Resetting %s dataplane", self.__class__.__name__)

    def _cleanupReal(self):
        # FIXME: need to refine what would be different
        self.resetState()

    def _runCommand(self, command, *args, **kwargs):
        return runCommand(self.log, command, *args, **kwargs)
