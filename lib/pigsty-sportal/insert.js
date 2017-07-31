var debug = require('debug')('pigsty-sportal');
var PigstyPlugin = require('pigsty-plugin');
var moment = require('moment');

Insert.prototype.constructor = Insert;

var TCP = 6;
var UDP = 17;
var ICMP = 1;

function tcpflags(flags) {
  var val = 0;

  var keys = Object.keys(flags);
  var pos = keys.length - 1;
  for (var pos; pos >= 0; pos--) {
      var k = keys[pos];
      var flag = flags[k];
      if (flag) {
            val = val | (1 << (keys.length - 1 - pos));
          }
    };
  return val;
};

function Insert(options) {
  var self = this;

  self.pool = options.pool;
  self.encoding = options.encoding || 'hex';
  self.sensors = options.sensors;
  self.signatures = options.signatures;
  self.event = options.event;
  self.utc = true;

  // if set, this will insert events into the databaes's local time.
  if (options.localtime) {
    self.utc = false;
  }
};

Insert.prototype._add_payload = function(callback) {
  var self = this;

  if (self.event.packets && self.event.packets.length > 0) {
    var data = self.event.packets[0].bytes;

    // TODO: other encodings
    if (self.encoding == 'base64' || self.encoding == 'hex') {
      var data = data.toString(self.encoding).toUpperCase();
      var query = "INSERT INTO `payloads` (`event_id`, `payloads`) " +
      "VALUES (?, ?)";

      var params = [
        self.event_id,
        data
      ]; 
      
      self.pool.query(query, params, function (error, results, fields) {
	  	  if (error) {
	  	  	return callback(error);
	  	  }

	  	  callback(null);
	    });
    } else {
      console.error("unsupported encoding: ", self.encoding);
      callback();
    }
 
  } else {
    return callback();
  }
};

Insert.prototype._add_udp_short = function(event, callback) {
  var self = this;

  var query = "INSERT INTO `udp_headers` (`event_id`, `source_port`, `destination_port`) " +
    "VALUES (?, ?, ?)";

  var params = [
    self.event_id,
    event.source_port,
    event.dest_port
  ];

  self.pool.query(query, params, function (error, results, fields) {
  	if (error) {
  		return callback(error);
  	}

  	return callback(null);
  });
};

Insert.prototype._add_tcp_short = function(event, callback) {
  var self = this;

  var query = "INSERT INTO `tcp_headers` (`event_id`, `source_port`, `destination_port`, `flags`) " +
  "VALUES (?,?,?,?)";
 
  // XXX: setting 0 for flags.  I don't know what belongs here.
  var params = [
    self.event_id,
    event.source_port,
    event.dest_port,
    0
  ];

  self.pool.query(query, params, function (error, results, fields) {
  	if (error) {
  		return callback(error);
  	}

  	callback(null);
  });
};

Insert.prototype._add_icmp_short = function(event, callback) {
  var self = this;

  var query = "INSERT INTO " +
  "`icmp_headers` (`event_id`, `type`, `code`) " +
  "VALUES (?,?,?)";

  var event = self.event.event;

  // source_port is icmp type
  // and dest_port is code in unified2 event
  // http://manual.snort.org/node44.html
  var params = [
    self.event_id,
    event.source_port,
    event.dest_port
  ];

  self.pool.query(query, params, function (error, results, fields) {
  	if (error) {
  		return callback(error);
  	}

  	callback(null);
  });
};

Insert.prototype._add_ip_hdr_short = function(event, callback) {
  var self = this;

  var query = 'INSERT INTO `ip_headers`  (`event_id`, `source`, `destination`, `protocol`)' +
    'VALUES (?,?,?,?)';
  
  var params = [
    self.event_id,
    event.source_ip,
    event.destination_ip, 
    event.protocol
  ];

  var protocol = event.protocol;

  self.pool.query(query, params, function (error, results, fields) {
  	if (error) {
  		callback(error);
  	}

  	if (protocol == UDP) {
  		self._add_udp_short(event, callback);
  	} else if (protocol == TCP) {
  		self._add_tcp_short(event, callback);
  	} else if (protocol == ICMP) {
  		self._add_icmp_short(event, callback);
  	} else {
	  console.error("Unknown protocol: ", protocol, event);
      callback(null);
  	}
  });
};

Insert.prototype._add_udp = function(packet, callback) {
  var self = this;

  if (!packet.protocol_name == "UDP" || !packet.ip.udp) {
    return callback(); 
  }

  var query = "INSERT INTO " +
    "`udp_headers (`event_id`, `source_port`, `destination_port`, `length`, `checksum`) " +
    "VALUES (?, ?, ?, ?, ?)";

  var event = self.event.event;

  var params = [
    self.event_id,
    packet.ip.udp.sport,
    packet.ip.udp.dport, 
    packet.ip.udp.length,
    packet.ip.udp.checksum
  ];

  self.pool.query(query, params, function (error, results, fields) {
  	if (error) {
  		return callback(error);
  	}

  	callback(null);
  });
};

Insert.prototype._add_tcp = function(packet, callback) {
  var self = this;

  if (!packet.protocol_name == "TCP" || !packet.ip.tcp) {
    return callback(); 
  }

  var query = "INSERT INTO `tcp_headers` (`event_id`, `source_port`, `destination_port`, " +
  "        `sequence`, `ack`, `offset`, `reserved`, " +
  "        `flags`, `window`, `checksum`, `urgent_pointer`) " +
  "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

  var params = [
    self.event_id,
    packet.ip.tcp.sport,
    packet.ip.tcp.dport,
    packet.ip.tcp.seqno,
    packet.ip.tcp.ackno,
    packet.ip.tcp.header_bytes / 4,
    packet.ip.tcp.reserved,
    tcpflags(packet.ip.tcp.flags),
    packet.ip.tcp.window_size,
    packet.ip.tcp.checksum,
    packet.ip.tcp.urgent_pointer,
  ];

  self.pool.query(query, params, function (error, results, fields) {
  	if (error) {
  		return callback(error);
  	}

  	callback(null);
  });
};

Insert.prototype._add_icmp = function(packet, callback) {
  var self = this;

  if (!packet.protocol_name == "ICMP" || !packet.ip.icmp) {
    return callback(); 
  }

  var query = "INSERT INTO `icmp_headers` (`event_id`, `type`, `code`, `checksum`, `icmp_id`, `sequence`) " +
  "VALUES (?, ?, ?, ?, ?, ?)";
  
  var params = [
    self.event_id,
    packet.ip.icmp.type,
    packet.ip.icmp.code,
    packet.ip.icmp.checksum,
    packet.ip.icmp.id,
    packet.ip.icmp.sequence
  ];

  self.pool.query(query, params, function (error, results, fields) {
  	if (error) {
  		return callback(error);
  	}

  	callback(null);
  });
};

Insert.prototype._add_ip_hdr = function(event, callback) {
  var self = this;

  if (!self.event.packets || !self.event.packets.length > 0) {
    return self._add_ip_hdr_short(event, callback);
  };

  var packet = self.event.packets[0].packet;

  if (!packet)
    return self._add_ip_hdr_short(event, callback);

  if (!packet.ip) {
    debug("Missing ip header in packet", packet); 
    return callback("Missing ip header in packet");
  };

  var query = 'INSERT INTO `ip_headers`  (`event_id`, `source`, `destination`, `header_length`,' +
    "`type_of_service`, `length`, `ip_id`, `flags`, `offset`," +
    "`ttl`, `protocol`, `checksum`, `version`) " +
    'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
  
  var params = [
    self.event_id,
    event.source_ip,
    event.destination_ip, 
    packet.ip.header_length,
    0, // Type of Service
    packet.ip.total_length,
    packet.ip.identification, 
    0, // TODO: packet.ip.flags is 3 bits. make int?
    packet.ip.fragment_offset,   
    packet.ip.ttl,
    packet.ip.protocol,
    packet.ip.header_checksum,
    packet.ip.version
  ];

  self.pool.query(query, params, function (error, results, fields) {
  	if (error) {
  		return callback(error);
  	}

  	if (packet.ip.udp) {
  		self._add_udp(packet, callback);
  	} else if (packet.ip.tcp) {
  		self._add_tcp(packet, callback);
  	} else if (packet.ip.icmp) {
  		self._add_icmp(packet, callback);
  	} else {
  		callback(null);
  	}
  });
};

Insert.prototype._add_event = function(event, callback) {
  var self = this;
  var query = 'INSERT INTO `events` (`sensor_id`, `signature_id`, `created_at`)'
  var params;

  if (self.utc) {
    query += ' VALUES (?, ?, ?, ?)';
    var time = moment.unix(event.event_second).utc();
    params = [
      self.sensor_id,
      self.signature_id,
      time.format("YYYY-MM-DD HH:mm:ss")
    ];
  } else {
    query += ' VALUES (?, ?, ?, FROM_UNIXTIME(?))';
    params = [
      self.sensor_id,
      self.signature_id,
      event.event_second
    ];
  }

  self.pool.query(query, params, function (error, results, fields) {
  	if (error) {
  		callback(error);
  	}

    self.event_id = results.insertId;
  	callback(null);
  });
};

Insert.prototype._signature = function(event, callback) {
  var self = this;

  self.signatures.lookup(event, function(error, signature_id) {
    if (error) {
      callback(error);
    }

    self.signature_id = signature_id;
    callback();
  })
};

Insert.prototype.run = function() {
  var self = this;
  var event = self.event;

  if (!event || Object.keys(self.event) == 0) {
    return; 
  };

  if (!event.sensor) {
  	debug('No sensor for event: ', event);
  	return;
    // return self._error_and_end({ msg: "No sensor for event: " , event: event });
  };

  if (!event.event_type) {
    debug('missing event type: ', event);
    return;
    // return self._error_and_end("No event type for event: " + event);
  };

  self.sensors.lookup(event.sensor, function(error, sensor) {

    if (error) {
      debug(error);
      // return self._error_and_end(error);
    }

    self.sensor_id = sensor.id;

    self._signature(event.event, function(error) {

      if (error) {
      	debug(error);
        // return self._error_and_end(error);
      }

      self._add_event(event.event, function(error) { 
        // debug('adding event: ', sensor, self.event);
        if (error) {
          debug(error);
          // return self._error_and_end(error);
        }

        self._add_ip_hdr(event.event, function(error) {
          
          if (error) {
          	debug(error)
            // return self._error_and_end(err);
          }

          
          self._add_payload(function(error) {

            if (error) {
              debug(error)
              // return self._error_and_end(err);
            };
          })
        });

      })
   
    })
  });
};

module.exports = Insert;
