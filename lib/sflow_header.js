/**
 * SFLOW STATIC HEADER
 */

var helpers = require('../helpers');

const ipVersionTexts = [null,"IPv4","IPv6"];
var Header = function(buffer) {
    var self = this;
    this.Version = undefined;
    this.ipVersion = undefined;
    this.ipVersionText = undefined;
    this.ipAddress = undefined;
    this.SubAgentId = undefined;
    this.Sequence = undefined;
    this.UptimeMS = undefined;
    this.Samples = undefined;
    this.sizeInBytes = 0;
    var _construct = function() {
        let index = 0;
        self.Version = buffer.readUInt32BE(index);
        self.ipVersion = buffer.readUInt32BE(index+4);
        self.ipVersionText = ipVersionTexts[self.ipVersion] || "Unknown";

        if (self.ipVersion === 1) {
            self.ipAddress = helpers.ipv4decode(buffer.slice(8));
            index = 12;
        } else {
            self.ipAddress = helpers.ipv6decode(buffer.slice(8));
            index = 24;
        }

        self.SubAgentId = buffer.readUInt32BE(index);
        self.Sequence = buffer.readUInt32BE(index+4);
        self.UptimeMS = buffer.readUInt32BE(index+8);
        self.Samples = buffer.readUInt32BE(index+12);
        self.sizeInBytes = index+16;
    }
    _construct();
    return this;
};

module.exports = Header;