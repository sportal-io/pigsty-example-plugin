var debug = require('debug')('pigsty-mysql')
var PigstyPlugin = require('pigsty-plugin');

ExamplePlugin.prototype = new PigstyPlugin();
ExamplePlugin.prototype.constructor = PigstyPlugin;

function ExamplePlugin(options) {
  var self = this;
  PigstyPlugin.call(this, options);
  self.options = options;
};

ExamplePlugin.prototype.configure = function(callback) {
  // Any Logic We Want To Run When The Plugin Is First Initialized.
  debug('Configure Plugin: pigsty-example-plugin');
};

ExamplePlugin.prototype.start = function(callback) {
  // Any Logic We Want To Run When The Plugin Starts.
};

ExamplePlugin.prototype.stop = function(callback) {
  // Any Logic We Want To Run When The Plugin Stops.
};

ExamplePlugin.prototype.send = function(event) {
  // Process The Event Data - We Can Do Whatever We Want Here.
  console.log(event);
};

module.exports = function(options) {
  return new ExamplePlugin(options);
};
