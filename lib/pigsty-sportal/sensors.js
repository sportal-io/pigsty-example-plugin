var debug = require('debug')('pigsty-sportal');

function Sensor(options) {
  var self = this;
  options = options || {}
  self.pool = options.pool;
  self.sensor_id = 0;
};

Sensor.prototype.load = function(sensor, callback) {
  var self = this;

  self.lookup(sensor, function(error) {
    if (error) {
      return callback(error); 
    }
    
    callback(null);
  });
};

Sensor.prototype.lookup = function(sensor, callback) {
  var self = this;

  if (self.error) {
    return callback(error);
  };

  if (!sensor) {
    return callback("No sensor provided");
  };

  if (!sensor.name) {
    return callback("No sensor name provided");
  }

  sensor.interface = sensor.interface || "";
  sensor.filter = sensor.filter || null;
  sensor.name = sensor.name || ""; 
  sensor.encoding = sensor.encoding || null;
  sensor.detail = sensor.detail || null;

  var query = 'SELECT `id` FROM `sensors` WHERE \
  `hostname = ? and `interface` = COALESCE(?, `interface`) \
  and COALESCE(`filter`, -1) = COALESCE(?, `filter`, -1) \
  and COALESCE(`encoding`, -1) = COALESCE(?, `encoding`, -1) \
  and COALESCE(`detail`, -1) = COALESCE(?, `detail`, -1) \
  LIMIT 1';
  
  var params = [
    sensor.name,
    sensor.interface,
    sensor.filter,
    sensor.encoding,
    sensor.detail
  ];

  self.pool.query(query, params, function(error, results, fields) {
  	if (error) {
  		return callback(error);
  	}

  	var sensor = results[0];

  	if (sensor) {
      self.error = null;
      self.id = sensor.id; 
      return callback(null, sensor) ;
    }

    var query = 'INSERT INTO `sensors` (`hostname`, `interface`, \
    `filter`, `encoding`, `detail`) VALUES (?,?,?,?,?)';

    self.pool.query(query, params, function (error, results, fields) {
    	if (error) {
    		return callback(error);
    	}

    	self.id = results.insertId;
    	callback(error, results);
    });
  });
}

function Sensors(options) {
  var self = this;
  self.pool = options.pool;
  self.locked = false; // ghettolock 
  self.sensors = {};
};

Sensors.prototype.lookup = function(sensor, callback) {
  var self = this;
  var id = sensor.id;  

  if (self.sensors[id]) {
    return callback(null, self.sensors[id]);
  };
 
  if (self.locked) {
    // wait a couple of secs
    return setTimeout(function() {
      debug('sensors lock busy...', self.locked);
      self.lookup(sensor, callback); 
    }, 1000) 
  };

  self.locked = { sensor: sensor.name };

  var s = new Sensor({ pool: self.pool });

  s.load(sensor, function(error) {
    self.locked = false;

    if (error) {
      return callback(error); 
    } else {
      self.sensors[id] = s;
      return callback(null, self.sensors[id]);
    } 
  })
};

module.exports = Sensors;
