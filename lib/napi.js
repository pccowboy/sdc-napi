/*
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 *
 * The Networking API application
 */

var assert = require('assert');
var fs = require('fs');
var path = require('path');

var restify = require('restify');
var UUID = require('node-uuid');
var MultiError = require('verror').MultiError;

var endpoints = require('./endpoints');
var IP = require('./util/ip');



// --- NAPI object and methods



/*
 * NAPI constructor
 */
function NAPI(opts) {
  this.log = opts.log;
  this.config = opts.config;
  this.dataFile = path.normalize(__dirname + '/../data.json');
  if (path.existsSync(this.dataFile)) {
    this.log.info("reading data file '%s'", this.dataFile);
    this.data = JSON.parse(fs.readFileSync(this.dataFile, 'utf8'));
  } else {
    this.log.info("data file '%s' does not exist: populating initial data",
        this.dataFile);
    this.data = { networks: populateInitialNetworks(opts.config, opts.log) };
    fs.writeFileSync(this.dataFile, JSON.stringify(this.data, null, 2));
  }

  var server = this.server = restify.createServer({ name: 'Network API v. 0.0.1' });
  server.use(restify.acceptParser(server.acceptable));
  server.use(restify.bodyParser());
  server.use(restify.queryParser());
  server.on('after', restify.auditLogger({
        log: this.log.child({component: 'audit'})
      }));

  endpoints.registerEndpoints(server, this, this.log);
}


/*
 * Starts the server
 */
NAPI.prototype.start = function() {
  var self = this;
  this.server.listen(self.config.port, function() {
    self.log.info("%s listening at %s", self.server.name, self.server.url);
  });
}


/*
 * Writes the data file to disk
 */
NAPI.prototype.writeDataFile = function(callback) {
  fs.writeFile(this.dataFile, JSON.stringify(this.data, null, 2), callback); 
}



// --- Setup and validation


/*
 * Populates initial network data from the config file
 */
function populateInitialNetworks(config, log) {
  var networks = {};
  var missing = {};

  if (!config.hasOwnProperty('initialNetworks')) {
    log.info("No initial networks specified in config file");
    return {};
  }

  log.info("Loading initial networks from config file");

  // Required values for every logical network:
  var requiredValues = ['network', 'netmask', 'startIP', 'endIP'];

  // Optional values, with its default value if not found
  var optionalValues = {
    vlan: 0,
    resolvers: [],
    gateway: null
  };

  // Values that need to be validated as IP addresses
  var ipValues = ['network', 'netmask', 'startIP', 'endIP', 'gateway'];

  for (var name in config.initialNetworks) {
    var uuid = UUID.v4();
    networks[uuid] = { name: name };
    var net = config.initialNetworks[name];

    for (var v in requiredValues) {
      var val = requiredValues[v];
      if (!net.hasOwnProperty(val)) {
        if (!missing.hasOwnProperty(name)) {
          missing[name] = [];
        }
        missing[name].push(val);
      }
      // TODO: validate the value here
      networks[uuid][val] = net[val];
    }

    for (var v in optionalValues) {
      if (net.hasOwnProperty(v)) {
        // TODO: validate the value here
        networks[uuid][v] = net[v];
      } else {
        var defaultVal = optionalValues[v];
        if (defaultVal != null) {
          networks[uuid][v] = defaultVal;
        }
      }
    }

    for (var v in ipValues) {
      var val = ipValues[v];
      var net = networks[uuid];
      if (!net.hasOwnProperty(val)) {
        continue;
      }

      var addr = net[val];
      var ipNum = IP.addressToNumber(addr);
      if (!ipNum) {
        throw new Error(val + " IP '" + addr + "' for network '" + net.name + "' is not valid.");
      }
      networks[uuid][val] = ipNum;
    }

    var resolvers = [];
    for (var v in networks[uuid].resolvers) {
      var val = networks[uuid].resolvers[v];
      var ipNum = IP.addressToNumber(val);
      if (!ipNum) {
        throw new Error("Resolver IP '" + val + "' for network '" + networks[uuid].name + "' is not valid.");
      }
      resolvers.push(ipNum);
    }
    networks[uuid].resolvers = resolvers;
  }

  if (Object.keys(missing).length != 0) {
    var errors = Object.keys(missing).reduce(function(acc, n) {
      acc.push(new Error("config.initialNetworks: network '" + n +
          "' is missing keys: " + JSON.stringify(missing[n])));
      return acc;
    }, []);
    throw new MultiError(errors);
  }

  // XXX: only allocate the top half of the range while we still have MAPI
  for (var uuid in networks) {
    var net = networks[uuid];
    net.startIP = net.startIP + ( (net.endIP - net.startIP) / 2);
  }

  log.info({ data: networks }, "Initial network data loaded");

  return networks;
}


/*
 * Creates a new NAPI server
 */
function createServer(opts) {
  assert.ok(opts, 'Must supply options');
  assert.ok(opts.hasOwnProperty('log'), 'Must supply logger');
  assert.ok(opts.hasOwnProperty('configFile'), 'Must supply configFile');

  var log = opts.log;
  log.info("Loading config from '" + opts.configFile + "'");
  var config = JSON.parse(fs.readFileSync(opts.configFile, 'utf-8'));

  var configRequired = {
    port: 'port number',
    macOUI: 'MAC address OUI for provisioning nics'
  };

  for (var req in configRequired) {
    // TODO: validate here too
    assert.ok(config.hasOwnProperty(req),
        "Missing config file option '" + req + "' (" + configRequired[req] + ")");
  }

  if (config.hasOwnProperty('logLevel')) {
    log.info("Setting log level to '%s'", config.logLevel);
    log.level(config.logLevel);
  }

  return new NAPI({
    log: log,
    config: config
  });
}



// --- Exports

module.exports = {
  createServer: createServer
};