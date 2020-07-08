var helpers = {}

let ipv4decode = function (buf) {
    var ip = buf.readUInt32BE(0);
    return (parseInt(ip/16777216)%256)+"."+(parseInt(ip/65536)%256)+"."+(parseInt(ip/256)%256)+"."+(ip%256);
}

let ipv6decode = function (buf) {
    return buf.toString('hex',0,16);
}

helpers.ipv4decode = ipv4decode;
helpers.ipv6decode = ipv6decode;

module.exports = helpers