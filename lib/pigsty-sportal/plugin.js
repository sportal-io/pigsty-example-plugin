var debug = require('debug')('pigsty-sportal');
var PigstyPlugin = require('pigsty-plugin');
var mysql = require('mysql');
var Sensors = require('./sensors');
var Signatures = require('./signatures');
var Insert = require('./insert');

Sportal.prototype = new PigstyPlugin();
Sportal.prototype.constructor = PigstyPlugin;

function Sportal(options) {
  PigstyPlugin.call(this, options);
  this.options = options;
};

Sportal.prototype.configure = function(callback) {
  // Any Logic We Want To Run When The Plugin Is First Initialized.
  debug('Configure Plugin: pigsty-example-plugin');
};

Sportal.prototype.start = function(callback) {
  var self = this;

  // Start Mysql Pool
  this.pool  = mysql.createPool({
    connectionLimit : self.options.max_pool_size,
    host            : self.options.host,
    user            : self.options.user,
    password        : self.options.password,
    database        : self.options.database
  });

  self.sensors = new Sensors({ pool: this.pool });
  self.signatures = new Signatures({ pool: self.pool });
  self.start_time = new Date().getTime();
  
  self.emit('ready');
};

Sportal.prototype.stop = function(callback) {
  var self = this;

  self.emit('end'); 
};

Sportal.prototype.send = function(event) {
  var self = this;
  
  self.pending += 1;

  // tell the parser we are full if we get > 
  // 2000 events in the queue.
  if (self.pending > 2000 && !self.paused) {
    self.emit('full');
    self.paused = setInterval(function() {
      if (self.pending < 1500 && self.paused) {
        clearInterval(self.paused);
        self.paused = null;
        self.emit('ok');
      }
    }, 500);
  }

  self.pending -= 1;

  var inserter = new Insert({
    pool: pool,
    event: event,
    sensors: self.sensors,
    signatures: self.signatures,
    encoding: self.options.encoding,
    localtime: self.options.localtime
  });

  inserter.run();
};

module.exports = function(options) {
  return new Sportal(options);
};
