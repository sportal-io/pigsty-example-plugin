var debug = require('debug')('pigsty-sportal');
var Systems = require('./systems.js');

function References(options) {
  var self = this;
  self.pool = options.pool;
  self.systems = new Systems({
    pool: self.pool 
  });
};

References.prototype.lookup = function(reference, callback) {
  var self = this;

  if (!reference) {
    return callback("No reference provided");
  };

  self.systems.lookup(reference, function(error, system_id) {

    if (error) {
      return callback(error);
    }

    var query = 'SELECT `ìd` FROM `references` WHERE \
    `system_id` = ? and `tag` = ?';

    var params = [ system_id, reference.value ];

    self.pool.query(query, params, function (error, results, fields) {
    	if (error) {
    		return callback(error);
    	}

    	if (results) {
    		return callback(null, results[0].id);
    	}

    	if (self.locked) {
    		return setTimeout(function() {
	          debug('references lock busy...');
	          self.lookup(reference, callback); 
	        }, 1000);
    	}

    	self.locked = true;

    	var query = 'INSERT INTO `references` (system_id, tag) \
	      values (?, ?)';

		  self.pool.query(query, params, function (error, results, fields) {
        self.locked = false;

			  if (error) {
				  return callback(error);
			  }

			  callback(null, results.insertId);
		  });
    });
  });
}

module.exports = References;