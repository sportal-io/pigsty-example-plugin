var debug = require('debug')('pigsty-sportal');
var References = require('./references');
var Classifications = require('./classifications');
var crypto = require('crypto');

var md5sum = function(data) {
  return crypto.createHash('md5').update(data).digest("hex");
};

function Signatures(options) {
  var self = this;
  self.pool = options.pool;
  self._load_cache();

  self.references = new References({
    pool: self.pool
  })
  self.classifications = new Classifications({
    pool: self.pool
  });
  self.locked = false; // ghettolock 
  self.signatures = {};
  self.pending = [];
};

Signatures.prototype._load_cache = function() {
  var self = this;

  var query = 'SELECT `id`, `sid`, `name`, `generator_id`, `revision` FROM `signatures`';

  self.pool.query(query, function (error, results, fields) {
    if (!error) {

      for (var i in results) {
        var signature = results[i];
        var id =  signature.sid 
        + "_" + signature.generator_id 
        + "_" + signature.revision 
        + "_" + signature.name;  

        self.signatures[id] = signature.id;
      }
   
      debug("loaded cache with signatures: ", i);
      self._cache_loaded = true;
    } else {
      console.error("error populating cache:", error);
    }
  });
}

Signatures.prototype._add_reference = function(reference, sequence, signature_id, callback) {
  var self = this;

  self.references.lookup(reference, function(error, reference_id) {
    if (error) {
      return callback(error); 
    }

    var query = self.db('INSERT INTO `reference_signature` (`signature_id`, `sequence`, `reference_id`)\
                         VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE `signature_id` = `signature_id`');

    var params = [
      signature_id,
      sequence,
      reference_id
    ];

    self.pool.query(query, params, function (error, results, fields) {
      if (error) {
        return callback(error);
      }

      callback();
    });
  });
}

Signatures.prototype._fetch = function(event, callback) {
  var self = this;

  event.classification = event.classification || { name: 'unknown', description: 'unknown', severity: 1 };

  self.classifications.lookup(event.classification, function(error, classification_id) {

    var query = 'SELECT `id` FROM `signatures` WHERE \
    `id` = ? and `generator_id` = ? and `revision` = ? and `name` = ?';

    var params = [
      event.signature_id,
      event.generator_id,
      event.signature_revision,
      event.signature.name
    ];

    self.pool.query(query, params, function (error, results, fields) {
      if (error) {
        return callback(error);
      }

      var signature = results[0] || {};

      var signature_id = signature.id;

      if (signature_id) {
        return callback(null, signature_id);
      }

      // otherwise, insert
      var query = 'INSERT INTO `signatures` (`sid`, `generator_id`, \
      `classification_id`, `name`, `priority`, `revision`) values (?,?,?,?,?,?) on duplicate key update sid = sid;';

      var params = [
        event.signature_id,
        event.generator_id,
        classification_id,
        event.signature.name,
        event.classification.severity,
        event.signature_revision
      ];

      self.pool.query(query, params, function (error, results, fields) {
        if (error) {
          return callback(error);
        }

        var signature_id = results.insertId;

        var references = event.signature.references || [];
        var todo = references.length;
        var position = 0;

        var add = function() {
          position += 1;

          if (todo == 0) {
            return callback(error, signature_id);
          }

          todo--;

          var references = references.pop();

          self._add_reference(reference, position, signature_id, function(error) {
            if (error) {
              return callback(error);
            }

            add();
          });
        }

        add();
      });
    });
  });
}

Signatures.prototype.lookup = function(event, callback) {
  var self = this;

  if (!event) {
    return callback("No event provided");
  };

  if (!event.signature_id) {
    return callback("No signature_id provided");
  };

  event.generator_id = event.generator_id || 1;

  event.signature = event.signature || { 
    references: [],
    name: 'Snort Alert [' + event.signature_id + ':' + event.generator_id + ':0]'
  };
  
  var id = event.signature_id 
      + "_" + event.generator_id
      + "_" + event.signature_revision
      + "_" + event.signature.name;  

  if (self.signatures[id]) {
    return callback(null, self.signatures[id]);
  };


  if (self.locked) {
    // wait a couple of secs
    return setTimeout(function() {
      debug('signatures lock busy...', event.event_id);
      self.lookup(event, callback); 
    }, 500); 
  }


  self.locked = { event: event.event_id };

  self._fetch(event, function(error, signature) {
    debug("loading signature: ", signature);
    self.locked = false;
    if (error) {
      return callback(error); 
    } else {
      self.signatures[id] = signature;
      return callback(null, self.signatures[id]);
    } 
  });
};

module.exports = Signatures;
