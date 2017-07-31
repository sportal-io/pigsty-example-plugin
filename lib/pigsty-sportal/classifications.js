
function Classifications(options) {
  var self = this;
  self.pool = options.pool;
  self.classifications = {};
};

Classifications.prototype._fetch = function(classification, callback) {
  var self = this;

  var query = 'SELECT `id` FROM `classifications` WHERE \
  `name` = ? limit 1';
  
  var params = [ classification.name ];

  self.pool.query(query, params, function (error, results, fields) {
    if (error) {
      return callback(error);
    }

    var signature = results[0];

    if (results[0]) {
      return callback(null, signature.id);
    }

    var query = 'INSERT INTO `classifications` (name) values (?)';

    self.pool.query(query, params, function (error, results, fields) {
      callback(error, results.insertId);
    });
  });
}

Classifications.prototype.lookup = function(classification, callback) {
  var self = this;
  
  if (!classification) {
    return callback("No classification provided");
  };

  if (self.classifications[classification.name]) {
    return callback(null, self.classifications[classification.name]);
  };

  // if (self.locked) {
  //   // wait a couple of secs
  //   return setTimeout(function() {
  //     debug('classifications lock busy...');
  //     self.lookup(classification, callback); 
  //   }, 1000) 
  // }

  // self.locked = true;

  self._fetch(classification, function(error, id) {
    // self.locked = false;
    if (error) {
      return callback(error); 
    } else {
      self.classifications[classification.name] = id;
      return callback(null, self.classifications[classification.name]);
    } 
  })
};


module.exports = Classifications;