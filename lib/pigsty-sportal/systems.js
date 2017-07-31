function Systems(options) {
  var self = this;
  self.pool = options.pool;
  self.systems = {};
  self.locked = false; // ghettolock 
};

Systems.prototype._fetch = function(reference, callback) {
  var self = this;

  var query = 'SELECT `id` from `systems` WHERE \
  `name` = ? LIMIT 1';

  var params = [ reference.key ];

  self.pool.query(query, params, function (error, results, fields) {
    if (error) {
        return callback(error);
    }

    if (results) {
        return callback(null, results[0].id)
    }

    // otherwise, insert

    var query = 'INSERT INTO `systems` (name) values (?)';

    self.pool.query(query, params, function(error, results, fields) {
        if (error) {
            return callback(error);
        }

        callback(null, results.insertId);
    });
  });
}

Systems.prototype.lookup = function(reference, callback) {
  var self = this;

  if (!reference) {
    return callback("No reference provided");
  };

  if (self.systems[reference.key]) {
    return callback(null, self.systems[reference.key]);
  };

  if (self.locked) {
    // wait a couple of secs
    return setTimeout(function() {
      debug('references lock busy...');
      self.lookup(reference, callback); 
    }, 1000) 
  }

  self.locked = true;

  self._fetch(reference, function(err, id) {
    self.locked = false;
    if (err) {
      return callback(err); 
    } else {
      self.systems[reference.key] = id;
      return callback(null, self.systems[reference.key]);
    } 
  })
};


module.exports = Systems;