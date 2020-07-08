var SflowPacket = require('./lib/packet');
const VERSION_SFLOW5 = 5

var Deserializer = function () {
    var self = this;
    this.deserialize = function (buffer) {
        const version = buffer.readUInt32BE(0);
        switch (version) {
            case VERSION_SFLOW5:
                if (typeof SflowPacket == 'function') {
                    return new Promise(function (resolve, reject) {
                        try {
                            var ParsedPacket = new SflowPacket(buffer);
                            resolve(ParsedPacket);
                        } catch (e) {
                            reject(e);
                        }
                    });
                } else {
                    return console.error('Invalid Packet');
                }
            default:
                console.error("Version unsupported!")
                break;
        }
    };
    return this;
}

module.exports = function () {
    return new Deserializer();
}