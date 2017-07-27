var debug = require('debug')('pigsty-sportal');

function RefSystems(options) {
  var self = this;
  self.pool = options.pool;
  self.ref_systems = {};
  self.locked = false; // ghettolock 
};

function References(options) {
  var self = this;
  self.pool = options.pool;
  self.ref_systems = new RefSystems({
    pool: self.pool 
  });
};

References.prototype.lookup = function(reference, callback) {
  var self = this;

  if (!reference) {
    return callback("No reference provided");
  };

  self.ref_systems.lookup(reference, function(error, ref_system_id) {

    if (error) {
      return callback(error);
    }

    var query = 'select ref_id from reference where \
    ref_system_id = ? and ref_tag = ?';

    var params = [ ref_system_id, reference.value ];

    self.pool.query(query, params, function (error, results, fields) {
    	if (error) {
    		return callback(error);
    	}

    	if (results) {
    		return callback(null, results[0].ref_id);
    	}

    	if (self.locked) {
    		return setTimeout(function() {
	          debug('references lock busy...');
	          self.lookup(reference, callback); 
	        }, 1000);
    	}

    	self.locked = true;

    	var query = 'insert into reference (ref_system_id, ref_tag) \
	      values (?,?)';

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