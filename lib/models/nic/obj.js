/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2016, Joyent, Inc.
 */

/*
 * nic model object
 */

'use strict';

var assert = require('assert-plus');
var BUCKET = require('./bucket').BUCKET;
var constants = require('../../util/constants');
var errors = require('../../util/errors');
var fmt = require('util').format;
var mod_moray = require('../../apis/moray');
var mod_portolan_moray = require('portolan-moray');
var mod_net = require('../network');
var mod_ip = require('../ip');
var util_ip = require('../../util/ip');
var util_mac = require('../../util/mac');
var vasync = require('vasync');



// --- Globals



// Boolean nic parameters: if it's true, display it when serializing.  If
// it's false, don't serialize it.
var BOOL_PARAMS = [
    'allow_dhcp_spoofing',
    'allow_ip_spoofing',
    'allow_mac_spoofing',
    'allow_restricted_traffic',
    'allow_unfiltered_promisc',
    'underlay'
];

// Read-only parameters from the network that will be serialized in the nic
// object.
var NET_PARAMS = [
    'fabric',
    'gateway_provisioned',
    'internet_nat',
    'mtu',
    'netmask',
    'nic_tag',
    'resolvers',
    'routes',
    'vlan_id'
];

var OPTIONAL_PARAMS = [
    'cn_uuid',
    'model',
    'nic_tag'
];



// --- Internal



/**
 * Adds an IP and network object to a nic object (if required)
 */
function addIPtoNic(app, log, res, callback) {
    var ipaddrs;

    if (res.params.ipaddrs) {
        ipaddrs = res.params.ipaddrs;
    } else if (res.params.ip) {
        ipaddrs = [ res.params.ip ];
    } else {
        return callback(null, res);
    }

    if (!(res.params.network_uuid || res.params.network_uuids)) {
        return callback(null, res);
    }

    var network_cache = new mod_net.NetworkCache(app, log);
    var network_uuids = {};
    var network4_uuid = res.params.network_uuid;
    var network4 = null;
    var ips = [];

    function _addIP_getIP(ip, cb) {
        var network;
        if (network_uuids.hasOwnProperty(ip)) {
            network = network_uuids[ip];
        } else if (network4 !== null) {
            network = network4;
        } else {
            cb(new Error('no network available for ' + ip));
            return;
        }

        var getOpts = {
            app: app,
            log: log,
            params: {
                ip: ip,
                network: network,
                network_uuid: network.uuid
            }
        };
        mod_ip.get(getOpts, function (e, r) {
            if (r) {
                ips.push(r);
            }
            return cb(e);
        });
    }

    return vasync.pipeline({
        funcs: [
            function _addIP_getNetwork4(_, cb) {
                if (network4_uuid === undefined) {
                    cb();
                    return;
                }
                network_cache.get(network4_uuid, function (e, r) {
                    log.debug({ error: e, result: r },
                        'got IPv4 network for uuid ' + network4_uuid);
                    if (r) {
                        network4 = r;
                    }
                    return cb(e);
                });
            },
            function _addIP_getNetworks(_, cb) {
                if (!res.params.hasOwnProperty('network_uuids')) {
                    cb();
                    return;
                }
                vasync.forEachParallel({
                    'inputs': Object.keys(res.params.network_uuids),
                    'func': function (ip, cb2) {
                        var uuid = res.params.network_uuids[ip];
                        network_cache.get(uuid, function (err, network) {
                            if (res) {
                                network_uuids[ip] = network;
                            }
                            cb2(err);
                        });
                    }
                }, cb);
            },
            function _addIP_getIPs(_, cb) {
                vasync.forEachParallel({
                    'inputs': ipaddrs,
                    'func': _addIP_getIP
                }, cb);
            }
        ]
    }, function (err2) {
        if (err2) {
            log.error(err2, 'addIPtoNic: Error getting IP or network');
            return callback(new errors.InternalError(err2));
        }

        if (log.trace()) {
            log.trace({
                ips: ips.map(function (ip) { return ip.serialize(); }),
                network4: network4.serialize(),
                network_uuids: network_uuids
            }, 'added IP and network');
        }

        if (ips.length > 0) {
            res.ips = ips;
        }

        return callback(null, res);
    });
}



// --- Nic object



/**
 * Nic model constructor
 */
function Nic(params) {
    assert.object(params, 'params');
    assert.ok(params.mac, 'mac (number / string) is required');
    assert.string(params.owner_uuid, 'owner_uuid');
    assert.string(params.belongs_to_uuid, 'belongs_to_uuid');
    assert.string(params.belongs_to_type, 'belongs_to_type');
    assert.optionalString(params.model, 'model');
    assert.optionalString(params.nic_tag, 'nic_tag');
    assert.optionalString(params.state, 'state');
    assert.optionalArrayOfString(params.ipaddrs, 'ipaddrs');
    assert.optionalString(params.ipaddr, 'ipaddr');
    assert.optionalNumber(params.ip, 'ip');

    params.state = params.state || constants.DEFAULT_NIC_STATE;

    // Allow mac to be passed in as a number or address, but the internal
    // representation is always a number
    var mac = params.mac;
    // XXX - isNaN() is not safe here '' coerces to 0, which we don't want.
    if (isNaN(mac)) {
        mac = util_mac.macAddressToNumber(params.mac);
    }
    assert.ok(mac, fmt('invalid MAC address "%s"', params.mac));
    params.mac = mac;

    if (params.hasOwnProperty('nic_tags_provided_arr')) {
        params.nic_tags_provided = params.nic_tags_provided_arr;
        if (params.nic_tags_provided.length === 0) {
            delete params.nic_tags_provided;
            delete params.nic_tags_provided_arr;
        }
    } else {
        mod_moray.valToArray(params, 'nic_tags_provided');
        if (params.nic_tags_provided && params.nic_tags_provided.length === 0) {
            delete params.nic_tags_provided;
        }
    }

    if (params.hasOwnProperty('primary_flag')) {
        params.primary = params.primary_flag;
    }

    this.params = params;

    if (params.hasOwnProperty('etag')) {
        this.etag = params.etag;
    } else {
        this.etag = null;
    }

    this.ips = null;

    if (params.hasOwnProperty('primary') &&
        typeof (params.primary) !== 'boolean') {
        this.params.primary = params.primary === 'true' ? true : false;
    }

    Object.seal(this);
}


Object.defineProperty(Nic.prototype, 'mac', {
    get: function () { return this.params.mac; },
    set: function (val) { this.params.mac = val; }
});


/**
 * Returns an object suitable for passing to a moray batch
 */
Nic.prototype.batch = function nicBatch(opts) {
    var self = this;
    var batch = [
        {
            bucket: BUCKET.name,
            key: this.mac.toString(),
            operation: 'put',
            value: this.raw(),
            options: {
                etag: this.etag
            }
        }
    ];

    if (opts && opts.migration) {
        // If we're migrating, don't do any of the updates below - they
        // can end up modifying the content of the other nics in the batch
        // out from under them, which renders their etags invalid.  This in
        // turn causes the batch to fail.
        return batch;
    }

    if (this.params.primary) {
        batch.push({
            bucket: BUCKET.name,
            fields: {
                primary_flag: 'false'
            },
            filter: fmt('(&(belongs_to_uuid=%s)(!(mac=%d)))',
                this.params.belongs_to_uuid, this.mac),
            operation: 'update'
        });
    }

    if (this.isUnderlay()) {
        // This is an underlay vnic - add it to the portolan underlay table
        // so other CNs can communicate with it.
        //
        // XXX: The below isn't quite right, since underlay nics should only
        // have a single IP address
        this.ips.forEach(function (ip) {
            batch.push(mod_portolan_moray.underlayMappingBatch({
                cn_uuid: self.params.belongs_to_uuid,
                ip: ip.v6address,
                port: constants.VXLAN_PORT
            }));
        });
    }

    this.ips.forEach(function (ip) {
        var network = ip.params.network;

        if (ip.isFabricGateway()) {
            network.gateway_provisioned = true;
            batch.push(network.batch());
        }
    });

    if (this.isFabric()) {
        // This is a fabric vnic - add it to the portolan overlay table
        // so other VMs on the fabric can communicate with it.
        // XXX - suspect spurious updates from net-agent PUTs
        this.ips.forEach(function (ip) {
            var v6address = ip.v6address;
            var network = ip.params.network;
            var vnet_id = network.vnet_id;
            var vlan_id = network.params.vlan_id;

            batch.push(mod_portolan_moray.overlayMappingBatch({
                cn_uuid: self.params.cn_uuid,
                deleted: false,
                ip: v6address,
                mac: self.mac,
                vnet_id: vnet_id
            }));

            // Poor factoring of the create/update code means that this section
            // is a no-op for updates of type 'update', which are instead
            // created in update#updateParams - specifically, opts.vnetCns will
            // be empty here in that case. This section does cover nic creation
            // and updates of type 'provision'.
            var _vl3batch = mod_portolan_moray.vl3CnEventBatch({
                vnetCns: opts.vnetCns,
                vnet_id: vnet_id,
                ip: v6address,
                mac: self.mac,
                vlan_id: vlan_id
            });

            opts.log.debug({
                vnet_id: vnet_id,
                ip: v6address,
                mac: self.mac,
                vlan: vlan_id,
                key: _vl3batch.uuid,
                batch: _vl3batch
            }, 'creating vl3 logs');

            batch = batch.concat(_vl3batch);
        });
    }

    return batch;
};


/**
 * Returns a moray batch that deletes this nic from all moray tables
 */
Nic.prototype.delBatch = function nicDelBatch(opts) {
    var self = this;
    var batch = [
        {
            bucket: BUCKET.name,
            key: this.mac.toString(),
            operation: 'delete'
        }
    ];

    // XXX: what to do if this was the primary nic?

    if (this.isUnderlay()) {
        // This is an underlay vnic - remove it from the portolan underlay table
        // so other CNs can no longer reach it.

        batch.push(mod_portolan_moray.underlayMappingDelBatch({
            cn_uuid: this.params.belongs_to_uuid
        }));
    }

    this.ips.forEach(function (ip) {
        var network = ip.params.network;

        if (ip.isFabricGateway()) {
            network.gateway_provisioned = false;
            batch.push(network.batch());
        }
    });

    if (this.isFabric()) {
        // This is a fabric vnic - add it to the portolan overlay table
        // so other VMs on the fabric can communicate with it.
        var vnet_id = this.representativeNet().vnet_id;
        this.ips.forEach(function (ip) {
            var v6address = ip.v6address;

            batch.push(mod_portolan_moray.overlayMappingBatch({
                cn_uuid: self.params.cn_uuid,
                deleted: true,
                ip: v6address,
                mac: self.mac,
                vnet_id: vnet_id
            }));

            opts.log.debug({
                cns: opts.vnetCns,
                vnet_id: vnet_id,
                ip: v6address,
                etag: self.etag
            }, 'nic.delBatch specific opts');
        });

        var _vl2batch = mod_portolan_moray.vl2CnEventBatch({
            vnetCns: opts.vnetCns,
            vnet_id: vnet_id,
            mac: self.mac,
            existingNic: opts.existingNic
        });

        opts.log.debug({
            key: _vl2batch.uuid,
            mac: self.mac,
            vnet_id: vnet_id,
            batch: batch,
            logBatch: _vl2batch
        }, 'delBatch: creating vl2 shootdown logs for delete');

        batch = batch.concat(_vl2batch);
    }

    return batch;
};


/**
 * Returns true if this is a fabric nic
 */
Nic.prototype.isFabric = function isFabric() {
    var network = this.representativeNet();
    if (!this.ips || !network) {
        return false;
    }

    if (this.params.belongs_to_type === 'zone' && network.fabric &&
        this.params.cn_uuid) {
        return true;
    }

    return false;
};


/**
 * Returns true if this is an underlay nic
 */
Nic.prototype.isUnderlay = function isUnderlay() {
    var network = this.representativeNet();
    if (!this.ips || !network) {
        return false;
    }

    var underlayTag = constants.UNDERLAY_TAG;
    if (underlayTag && this.params.underlay &&
            this.params.belongs_to_type === 'server' &&
            network.nic_tag === underlayTag) {
        return true;
    }

    return false;
};

/**
 * Select one of the networks that this NIC is on to serve as a representative
 * network for grabbing properties that are common between all networks.
 */
Nic.prototype.representativeNet = function representativeNet() {
    for (var ip in this.ips) {
        return this.ips[ip].params.network;
    }
    return null;
};

/**
 * Returns the serialized form of the nic
 */
Nic.prototype.serialize = function nicSerialize() {
    var self = this;
    var macAddr = util_mac.ntoa(this.params.mac);
    var serialized = {
        belongs_to_type: this.params.belongs_to_type,
        belongs_to_uuid: this.params.belongs_to_uuid,
        mac: macAddr,
        owner_uuid: this.params.owner_uuid,
        primary: this.params.primary ? true : false,
        state: this.params.state
    };

    var gateways = {};
    var gennet = null;

    if (this.ips && this.ips.length > 0) {
        serialized.network_uuids = {};
        serialized.ips = [];
        this.ips.forEach(function (ip) {
            var network = ip.params.network;
            var ipSer = ip.serialize().ip;
            var gateway;

            if (network.params.gateway) {
                gateway = network.params.gateway.toString();
            }

            // Select the first IPv4 address on the NIC as our
            // representative address
            if (serialized.ip === undefined && ip.type === 'ipv4') {
                gennet = network;
                serialized.ip = ipSer;
                serialized.network_uuid = network.uuid;
                if (gateway) {
                    serialized.gateway = gateway;
                }
            }

            var key = ipSer + '/' + network.subnetBits;

            serialized.network_uuids[key] = network.uuid;
            serialized.ips.push(key);
            if (gateway) {
                gateways[gateway] = true;
            }
        });
        serialized.ips.sort();
    }

    gateways = Object.keys(gateways);

    if (gateways.length > 0) {
        serialized.gateways = gateways;
    }

    var netSer;

    // If we don't have a network from the representative IP address, we
    // pick one of the IPv4 or IPv6 networks to serve as a generic network for
    // grabbing properties that will always be the same between them.
    if (gennet === null) {
        gennet = this.representativeNet();
    }

    if (gennet) {
        netSer = gennet.serialize();
        NET_PARAMS.forEach(function (param) {
            if (netSer.hasOwnProperty(param)) {
                serialized[param] = netSer[param];
            }
        });
    }

    // Allow the nic to override its network's nic tag
    OPTIONAL_PARAMS.forEach(function (param) {
        if (self.params.hasOwnProperty(param)) {
            serialized[param] = self.params[param];
        }
    });

    // If on a fabric network, the nic tag is special: it contains the
    // virtual network ID so compute nodes know what overlay network to
    // communicate on.
    if (gennet && gennet.fabric) {
        serialized.nic_tag = fmt('%s/%d', gennet.nic_tag, gennet.vnet_id);
    }

    if (this.params.hasOwnProperty('nic_tags_provided')) {
        serialized.nic_tags_provided = this.params.nic_tags_provided;
    }

    BOOL_PARAMS.forEach(function (param) {
        if (self.params[param]) {
            serialized[param] = true;
        }
    });

    return serialized;
};


/**
 * Returns the raw form of the nic suitable for storing in moray
 */
Nic.prototype.raw = function nicRaw() {
    var self = this;
    var raw = {
        mac: this.params.mac,
        owner_uuid: this.params.owner_uuid,
        belongs_to_uuid: this.params.belongs_to_uuid,
        belongs_to_type: this.params.belongs_to_type,
        primary_flag: this.params.primary ? true : false,
        state: this.params.state,
        v: BUCKET.version
    };

    var networks = {};
    var reprIP;

    if (this.ips) {
        raw.ipaddrs = [];
        raw.network_uuids = {};
        this.ips.forEach(function (ip) {
            assert.ok(ip instanceof mod_ip.IP, 'ip');
            if (reprIP === undefined && ip.type === 'ipv4') {
                reprIP = ip;
            }
            var key = ip.address.toString();
            var network_uuid = ip.params.network.uuid;
            raw.ipaddrs.push(key);
            raw.network_uuids[key] = network_uuid;
            networks[network_uuid] = true;
        });

        if (reprIP !== undefined) {
            raw.ipaddr = reprIP.address.toString();
            raw.network_uuid = reprIP.params.network.uuid;
            raw.ip = reprIP.address.toLong();
        }

        // We can't index/search on objects, so we create an array of UUIDs
        // of all networks that this NIC is on for querying.
        raw.networks = Object.keys(networks);
    } else {
        // Try to add what information we do have - for example, when doing
        // migrations, we don't have the fetched ip and network objects
        if (this.params.network_uuid) {
            raw.network_uuid = this.params.network_uuid;
        }

        if (this.params.ipaddr) {
            raw.ip = this.params.ipaddr.toLong();
            raw.ipaddr = this.params.ipaddr.toString();
        } else if (this.params.ip) {
            raw.ip = this.params.ip;
            raw.ipaddr = util_ip.ntoa(raw.ip);
        }
    }

    BOOL_PARAMS.forEach(function (param) {
        if (self.params[param]) {
            raw[param] = true;
        }
    });

    OPTIONAL_PARAMS.forEach(function (param) {
        if (self.params.hasOwnProperty(param)) {
            raw[param] = self.params[param];
        }
    });

    // Store nic_tags_provided as a string - this allows it to be indexed
    // properly in moray, which in turn allows searching on all of the values
    if (this.params.hasOwnProperty('nic_tags_provided')) {
        raw.nic_tags_provided =
            mod_moray.arrayToVal(this.params.nic_tags_provided);
        raw.nic_tags_provided_arr = this.params.nic_tags_provided;
    }

    return raw;
};



// --- Exports



/**
 * Creates a nic from the raw moray data
 */
function createFromRaw(opts, rec, callback) {
    opts.log.debug(rec, 'createFromRaw: creating nic');
    var params = rec.value;

    var newNic;
    try {
        newNic = new Nic(params);
    } catch (err) {
        return callback(err);
    }

    newNic.etag = rec._etag;

    return addIPtoNic(opts.app, opts.log, newNic, callback);
}



module.exports = {
    createFromRaw: createFromRaw,
    Nic: Nic
};
