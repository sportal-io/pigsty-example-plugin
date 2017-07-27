var debug = require('debug')('pigsty-sportal');
var PigstyPlugin = require('pigsty-plugin');
var mysql = require('mysql');

ExamplePlugin.prototype = new PigstyPlugin();
ExamplePlugin.prototype.constructor = PigstyPlugin;

function ExamplePlugin(options) {
  PigstyPlugin.call(this, options);
  this.options = options;
};

ExamplePlugin.prototype.configure = function(callback) {
  // Any Logic We Want To Run When The Plugin Is First Initialized.
  debug('Configure Plugin: pigsty-example-plugin');
};

ExamplePlugin.prototype.start = function(callback) {
  // Any Logic We Want To Run When The Plugin Starts.
  var self = this;

  // Start Mysql Pool
  this.pool  = mysql.createPool({
    connectionLimit : self.options.max_pool_size,
    host            : self.options.host,
    user            : self.options.user,
    password        : self.options.password,
    database        : self.options.database
  });


  emit('ready');
};

ExamplePlugin.prototype.stop = function(callback) {
  // Any Logic We Want To Run When The Plugin Stops.
  emit('end');
};

ExamplePlugin.prototype.send = function(event) {
  // Process The Event Data - We Can Do Whatever We Want Here.
  this.pool.query("select sig_id, sig_sid, sig_name, sig_gid, sig_rev from signature", function(error, results, fields) {
    console.log(results);
  });
  console.log(event);
};

module.exports = function(options) {
  return new ExamplePlugin(options);
};
