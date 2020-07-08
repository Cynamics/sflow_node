var util = require('util');
var helpers = require('../helpers');
var SflowHeader = require('./sflow_header');


// This is where the flows are built
let defaultFlowRecords = function (flow, buf) {
    switch (flow.format) {
        case 1:
            flow.type = "raw";
            flow.protocol = buf.readUInt32BE(8);
            flow.protocolText = [null,"ethernet",null,null,null,null,null,null,null,null,null,"IPv4","IPv6"][flow.protocol]||"unknown";
            flow.frameLen = buf.readUInt32BE(12);
            flow.frameStripped = buf.readUInt32BE(16);
            flow.hdrSize = buf.readUInt32BE(20);
            flow.header = buf.slice(24,24+flow.hdrSize);
            break;
        case 2:
            flow.type = "ethernet";
            flow.frameLen = buf.readUInt32BE(8);
            flow.srcMac = buf.toString('hex',12,18);
            flow.dstMac = buf.toString('hex',20,26);
            flow.frameType = buf.readUInt32BE(28);
            break;
        case 3:
            flow.type = "IPv4";
            flow.pktLen = buf.readUInt32BE(8);
            flow.ipProto = buf.readUInt32BE(12);
            flow.srcIp = helpers.ipv4decode(buf.slice(16));
            flow.dstIp = helpers.ipv4decode(buf.slice(20));
            flow.srcPort = buf.readUInt32BE(24);
            flow.dstPort = buf.readUInt32BE(28);
            flow.tcpFlags = buf.readUInt32BE(32);
            flow.tos = buf.readUInt32BE(36);
            break;
        case 4:
            flow.type = "IPv6";
            flow.pktLen = buf.readUInt32BE(8);
            flow.ipNextHeader = buf.readUInt32BE(12);
            flow.srcIp = helpers.ipv6decode(buf.slice(16));
            flow.dstIp = helpers.ipv6decode(buf.slice(32));
            flow.srcPort = buf.readUInt32BE(48);
            flow.dstPort = buf.readUInt32BE(52);
            flow.tcpFlags = buf.readUInt32BE(56);
            flow.ipPriority = buf.readUInt32BE(60);
            break;
        case 1001:
            flow.type = "extendedSwitch";
            flow.srcVlan = buf.readUInt32BE(8);
            flow.srcPriority = buf.readUInt32BE(12);
            flow.dstVlan = buf.readUInt32BE(16);
            flow.dstPriority = buf.readUInt32BE(20);
            break;
        case 1002:
            flow.type = "extendedRouter";
            flow.ipVersion = buf.readUInt32BE(8);
            flow.ipNextHop = flow.ipVersion==2?helpers.ipv6decode(buf.slice(12)):helpers.ipv4decode(buf.slice(12));
            flow.srcMaskLen = buf.readUInt32BE(flow.ipVersion*16);
            flow.dstMaskLen = buf.readUInt32BE(4+flow.ipVersion*16);
            break;
        case 1003:
            flow.type = "extendedGateway";
            b = buf.slice(8);
            flow.ipVersion = b.readUInt32BE(0);
            flow.ipNextHop = flow.ipVersion==2?helpers.ipv6decode(b.slice(4)):helpers.ipv4decode(b.slice(4));
            b = b.slice(flow.ipVersion*16-8);
            flow.routerAs = b.readUInt32BE(0);
            flow.srcAs = b.readUInt32BE(4);
            flow.srcPeerAs = b.readUInt32BE(8);
            flow.dstAsPath = [];
            for (i = b.readUInt32BE(12),b=b.slice(16);i;i--) {
                var as = {};
                as.type = b.readUInt32BE(0);
                as.typeText = [null,"as-set","sequence"][as.type]||"unknown";
                as.path = [];
                var x = b.readUInt32BE(4);
                for (b = b.slice(8);x;x--) { as.path.push(b.readUInt32BE(0));b = b.slice(4); }
                flow.dstAsPath.push(as);
            }
            flow.community = [];
            for (i = b.readUInt32BE(0),b= b.slice(4);i;i--) { flow.community.push(b.readUInt32BE(0)); b=b.slice(4); }
            flow.localPref = b.readUInt32BE(0);
            break;
        case 1004:
            flow.type = "extendedUser";
            flow.srcCharset = buf.readUInt32BE(8);
            flow.srcUserLen = buf.readUInt32BE(12);
            flow.srcUser = buf.toString('utf8',16,16+flow.srcUserLen);
            b = buf.slice(16+flow.srcUserLen);
            flow.dstCharset = b.readUInt32BE(0);
            flow.dstUserLen = b.readUInt32BE(4);
            flow.dstUser = b.toString('utf8',8,8+flow.dstUserLen);
            break;
        case 1005:
            flow.type = "extendedUrl";
            flow.direction = buf.readUInt32BE(8);
            flow.directionText = [null,"src","dest"][flow.direction]||"unknown";
            flow.urlLen = buf.readUInt32BE(12);
            flow.url = buf.toString('utf8',16,16+flow.urlLen);
            b = buf.slice(16+flow.urlLen);
            flow.hostLen = b.readUInt32BE(0);
            flow.host = buf.toString('utf8',4,4+flow.hostLen);
            break;
        case 1006:
            flow.type = "extendedMpls";
            b = buf.slice(8);
            flow.ipVersion = b.readUInt32BE(0);
            flow.ipNextHop = flow.ipVersion==2?helpers.ipv6decode(b.slice(4)):helpers.ipv4decode(b.slice(4));
            b = b.slice(16*flow.ipVersion-8);
            flow.mplsInStackLen = b.readUInt32BE(0);
            flow.mplsInStack = [];
            for (i=flow.mplsInStackLen,b= b.slice(4);i;i--) {
                flow.mplsInStack.push(b.readUInt32BE(0));b = b.slice(4);
            }
            flow.mplsOutStackLen = b.readUInt32BE(0);
            flow.mplsOutStack = [];
            for (i=flow.mplsOutStackLen,b= b.slice(4);i;i--) {
                flow.mplsOutStack.push(b.readUInt32BE(0));b = b.slice(4);
            }
            break;
        case 1007:
            flow.type = "extendedNat";
            b = buf.slice(8);
            flow.ipVersionSrc = b.readUInt32BE(0);
            flow.ipSrcAddr = flow.ipVersionSrc==2?helpers.ipv6decode(b.slice(4)):helpers.ipv4decode(b.slice(4));
            b = buf.slice(flow.ipVersionSrc*16-8);
            flow.ipVersionDst = b.readUInt32BE(0);
            flow.ipDstAddr = flow.ipVersionDst==2?helpers.ipv6decode(b.slice(4)):helpers.ipv4decode(b.slice(4));
            break;
        case 1008:
            flow.type = "extendedMplsTunnel";
            b = buf.slice(8);
            i = b.readUInt32BE(0);
            flow.tunnelName = b.toString('utf8',4,4+i);
            b = b.slice(4+i);
            flow.tunnelId = b.readUInt32BE(0);
            flow.tunnelCos = b.readUInt32BE(4);
            break;
        case 1009:
            flow.type = "extendedMplsVc";
            b = buf.slice(8);
            i = b.readUInt32BE(0);
            flow.vcName = b.toString('utf8',4,4+i);
            b = b.slice(4+i);
            flow.vcId = b.readUInt32BE(0);
            flow.vcCos = b.readUInt32BE(4);
            break;
        case 1010:
            flow.type = "extendedMplsFec";
            b = buf.slice(8);
            i = b.readUInt32BE(0);
            flow.mplsFTNDescr = b.toString('utf8',4,4+i);
            b = b.slice(4+i);
            flow.mplsFTNMask = b.readUInt32BE(0);
            break;
        case 1011:
            flow.type = "extendedMplsLvpFec";
            flow.mplsFecAddrPreﬁxLength = buf.readUInt32BE(8);
            break;
        case 1012:
            flow.type = "extendedVlanTunnel";
            flow.vlanStackLen = buf.readUInt32BE(8);
            flow.vlanStack = [];
            for (i=flow.vlanStackLen,b=buf.slice(12);i;i--) {
                flow.vlanStack.push(b.readUInt32BE(0)); b = b.slice(4);
            }
             break;
        default:
            flow.format = flow.format - flow.enterprise;
            throw new Error('unknown format');
    }
}

let pmacctFlowRecords = function (flow, buf) {
    switch(flow.format) {
        case 2: //SFLFLOW_EX_TAG    = (8800 << 12) + 2,
            flow.type = 'tag';
            flow.tag = buf.readUInt32BE(8);
            flow.tag2 = buf.readUInt32BE(12);
            break;
        default:
            flow.data = buf.slice(8, 8 + flow.length);
            break;
    }
}

// Enterprise
let readFlowRecords = function (buf) {
    var out = [];

    var n = buf.readUInt32BE(0);
    var b,i;

    for (buf = buf.slice(4);n;n--) {
        var record = {};
        record.format = buf.readUInt32BE(0);
        record.enterprise = parseInt(record.format/4096);
        record.format = record.format%4096;
        record.length = buf.readUInt32BE(4);
        //flow.data = buf.slice(8,8+flow.length);

        switch(record.enterprise) {
            case 0: //default
                defaultFlowRecords(record, buf);
                break;
            case 8800: //pmacct (vyatta, vyos) https://github.com/vincentbernat/pmacct/blob/master/src/sflow.h
                pmacctFlowRecords(record, buf);
                break;

            default:
                record.type='unknown';
                record.data = buf.slice(8, 8+record.length);
                break;
        }
        
        out.push(record);
    
        buf = buf.slice(8+record.length);
    }

    return out;
};


let readCounterRecords = function (buf) {
    var out = [];

    var n = buf.readUInt32BE(0);

    for (buf = buf.slice(4);n;n--) {
        var counter = {};
        counter.format = buf.readUInt32BE(0);
        counter.length = buf.readUInt32BE(4);
        //cnt.data = buf.slice(8,8+flow.length);

        switch (counter.format) {
            case 1:
                counter.ifIndex = buf.readUInt32BE(8);
                counter.ifType = buf.readUInt32BE(12);
                counter.ifSpeed = buf.readUInt32BE(16);
                counter.ifDirection = buf.readUInt32BE(20);
                counter.ifDirectionText = [null,"full-duplex","half-duplex","in","out"][counter.ifDirection]||"unknown";
                counter.ifStatus = buf.readUInt32BE(24);
                counter.ifStatusAdmin = (counter.ifStatus&1)?"up":"down";
                counter.ifStatusOper = (counter.ifStatus&2)?"up":"down";
                counter.ifInOctets = buf.readUInt32BE(28)*0x100000000 + buf.readUInt32BE(32);
                counter.ifInUcastPkts = buf.readUInt32BE(36);
                counter.ifInMulticastPkts = buf.readUInt32BE(40);
                counter.ifInBroadcastPkts = buf.readUInt32BE(44);
                counter.ifInDiscards = buf.readUInt32BE(48);
                counter.ifInErrors = buf.readUInt32BE(52);
                counter.ifInUnknownProtos = buf.readUInt32BE(56);
                counter.ifOutOctets = buf.readUInt32BE(60)*0x100000000 + buf.readUInt32BE(64);
                counter.ifOutUcastPkts = buf.readUInt32BE(68);
                counter.ifOutBroadcastPkts = buf.readUInt32BE(72);
                counter.ifOutDiscards = buf.readUInt32BE(76);
                counter.ifOutErrors = buf.readUInt32BE(80);
                counter.ifPromiscousMode = buf.readUInt32BE(84);
                break;
            case 2:
                counter.dot3StatsAlignmentErrors = buf.readUInt32BE(8);
                counter.dot3StatsFCSErrors = buf.readUInt32BE(12);
                counter.dot3StatsSingleCollisionFrames = buf.readUInt32BE(16);
                counter.dot3StatsMultipleCollisionFrames = buf.readUInt32BE(20);
                counter.dot3StatsSQETestErrors = buf.readUInt32BE(24);
                counter.dot3StatsDeferredTransmissions = buf.readUInt32BE(28);
                counter.dot3StatsLateCollisions = buf.readUInt32BE(32);
                counter.dot3StatsExcessiveCollisions = buf.readUInt32BE(36);
                counter.dot3StatsInternalMacTransmitErrors = buf.readUInt32BE(40);
                counter.dot3StatsCarrierSenseErrors = buf.readUInt32BE(44);
                counter.dot3StatsFrameTooLongs = buf.readUInt32BE(48);
                counter.dot3StatsInternalMacReceiveErrors = buf.readUInt32BE(52);
                counter.dot3StatsSymbolErrors = buf.readUInt32BE(56);
                break;
            case 3:
                counter.dot5StatsLineErrors = buf.readUInt32BE(8);
                counter.dot5StatsBurstErrors = buf.readUInt32BE(12);
                counter.dot5StatsACErrors = buf.readUInt32BE(16);
                counter.dot5StatsAbortTransErrors = buf.readUInt32BE(20);
                counter.dot5StatsInternalErrors = buf.readUInt32BE(24);
                counter.dot5StatsLostFrameErrors = buf.readUInt32BE(28);
                counter.dot5StatsReceiveCongestions = buf.readUInt32BE(32);
                counter.dot5StatsFrameCopiedErrors = buf.readUInt32BE(36);
                counter.dot5StatsTokenErrors = buf.readUInt32BE(40);
                counter.dot5StatsSoftErrors = buf.readUInt32BE(44);
                counter.dot5StatsHardErrors = buf.readUInt32BE(48);
                counter.dot5StatsSignalLoss = buf.readUInt32BE(52);
                counter.dot5StatsTransmitBeacons = buf.readUInt32BE(56);
                counter.dot5StatsRecoverys = buf.readUInt32BE(60);
                counter.dot5StatsLobeWires = buf.readUInt32BE(64);
                counter.dot5StatsRemoves = buf.readUInt32BE(68);
                counter.dot5StatsSingles = buf.readUInt32BE(72);
                counter.dot5StatsFreqErrors = buf.readUInt32BE(76);
                break;
            case 4:
                counter.dot12InHighPriorityFrames = buf.readUInt32BE(8);
                counter.dot12InHighPriorityOctets = buf.readUInt32BE(12)*0x100000000 + buf.readUInt32BE(16);
                counter.dot12InNormPriorityFrames = buf.readUInt32BE(20);
                counter.dot12InNormPriorityOctets = buf.readUInt32BE(24)*0x100000000 + buf.readUInt32BE(28);
                counter.dot12InIPMErrors = buf.readUInt32BE(32);
                counter.dot12InOversizeFrameErrors = buf.readUInt32BE(36);
                counter.dot12InDataErrors = buf.readUInt32BE(40);
                counter.dot12InNullAddressedFrames = buf.readUInt32BE(44);
                counter.dot12OutHighPriorityFrames = buf.readUInt32BE(48);
                counter.dot12OutHighPriorityOctets = buf.readUInt32BE(52)*0x100000000 + buf.readUInt32BE(56);
                counter.dot12TransitionIntoTrainings = buf.readUInt32BE(60);
                counter.dot12HCInHighPriorityOctets = buf.readUInt32BE(64)*0x100000000 + buf.readUInt32BE(68);
                counter.dot12HCInNormPriorityOctets = buf.readUInt32BE(72)*0x100000000 + buf.readUInt32BE(76);
                counter.dot12HCOutHighPriorityOctets = buf.readUInt32BE(80)*0x100000000 + buf.readUInt32BE(84);
                break;
            case 5:
                counter.vlan_id = buf.readUInt32BE(8);
                counter.octets = buf.readUInt32BE(12)*0x100000000 + buf.readUInt32BE(16);
                counter.ucastPkts = buf.readUInt32BE(20);
                counter.multicastPkts = buf.readUInt32BE(24);
                counter.broadcastPkts = buf.readUInt32BE(28);
                counter.discards = buf.readUInt32BE(32);
                break;
            case 1001:
                counter.cpuPerc5s = buf.readUInt32BE(8);
                counter.cpuPerc1m = buf.readUInt32BE(12);
                counter.cpuPerc5m = buf.readUInt32BE(16);
                counter.totalMem = buf.readUInt32BE(20)*0x100000000 + buf.readUInt32BE(24);
                counter.freeMem = buf.readUInt32BE(28)*0x100000000 + buf.readUInt32BE(32);
                break;
            default:
                throw new Error('unknown format');
        }

        out.push(counter);
        buf = buf.slice(8+counter.length);
    }

    return out;
}


/*
 * Packet Constructor
 * 
 */

var SflowPacket = function (buffer) {
    var self = this;

    self.header = new SflowHeader(buffer);
    buffer = buffer.slice(self.header.sizeInBytes);

    self.DataSets = [];

    for (var n = self.header.Samples;n;n--) {
        var sHdr = buffer.readUInt32BE(0);
        var flow = {};
        flow.enterprise = parseInt(sHdr/4096);
        flow.format = sHdr%4096;
        flow.length = buffer.readUInt32BE(4);
        if (flow.enterprise>0) {
            throw new Error('Unknown enterprise type');
        }

        flow.seqNum = buffer.readUInt32BE(8);

        switch (flow.format) {
            case 1:
                flow.sourceIdIndex = buffer.readUInt32BE(12) % 0x1000000;
                flow.sourceIdType = parseInt(buffer.readUInt32BE(12) / 0x1000000);
                flow.sourceIdTypeText = ["ifIndex","smonVlanDataSource","entPhysicalEntry"][flow.sourceIdType]||"Unknown";
                flow.samplingRate = buffer.readUInt32BE(16);
                flow.samplePool = buffer.readUInt32BE(20);
                flow.sampleDrops = buffer.readUInt32BE(24);
                flow.input = buffer.readUInt32BE(28);
                flow.output = buffer.readUInt32BE(32);
                flow.records = readFlowRecords(buffer.slice(36));
                break;
            case 2:
                flow.sourceIdIndex = buffer.readUInt32BE(12) % 0x1000000;
                flow.sourceIdType = parseInt(buffer.readUInt32BE(12) / 0x1000000);
                flow.sourceIdTypeText = ["ifIndex","smonVlanDataSource","entPhysicalEntry"][flow.sourceIdType]||"Unknown";
                flow.counters = readCounterRecords(buffer.slice(16));
                break;
            case 3:
                flow.sourceIdType = buffer.readUInt32BE(12);
                flow.sourceIdIndex = buffer.readUInt32BE(16);
                flow.sourceIdTypeText = ["ifIndex","smonVlanDataSource","entPhysicalEntry"][flow.sourceIdType]||"Unknown";
                flow.samplingRate = buffer.readUInt32BE(20);
                flow.samplePool = buffer.readUInt32BE(24);
                flow.sampleDrops = buffer.readUInt32BE(28);
                flow.inputFormat = buffer.readUInt32BE(32);
                flow.input = buffer.readUInt32BE(36);
                flow.outputFormat = buffer.readUInt32BE(40);
                flow.output = buffer.readUInt32BE(44);
                flow.records = readFlowRecords(buffer.slice(48));
                break;
            case 4:
                flow.sourceIdType = buffer.readUInt32BE(12);
                flow.sourceIdIndex = buffer.readUInt32BE(16);
                flow.sourceIdTypeText = ["ifIndex","smonVlanDataSource","entPhysicalEntry"][flow.sourceIdType]||"Unknown";
                flow.counters = readCounterRecords(buffer.slice(20));
                break;
            default:
                throw new Error('Unknown format type');
        }

        self.DataSets.push(flow);
        buffer = buffer.slice(flow.length+8);
    }
    return self;
}

module.exports = SflowPacket;