var debug = require('debug')('pigsty-sportal');
var References = require('./references');
var crypto = require('crypto');

var md5sum = function(data) {
  return crypto.createHash('md5').update(data).digest("hex");
};

function SigClasses(options) {
  var self = this;
  self.pool = options.pool;
  self.sig_classes = {};
};

function Signatures(options) {
  var self = this;
  self.pool = options.pool;
  self._load_cache();

  self.references = new References({
    pool: self.pool
  })
  self.sigclasses = new SigClasses({
    pool: self.pool
  });
  self.locked = false; // ghettolock 
  self.signatures = {};
  self.pending = [];
};

SigClasses.prototype._fetch = function(classification, callback) {
  var self = this;

  var query = 'select sig_class_id from sig_class where \
  sig_class_name = ? limit 1';
  
  var params = [ classification.name ];

  self.pool.query(query, params, function (error, results, fields) {
    if (error) {
      return callback(error);
    }

    var signature = results[0];

    if (results) {
      return callback(null, signature.sig_class_id);
    }

    var query = 'insert into sig_class (sig_class_name) values (?)';

    self.pool.query(query, params, function (error, results, fields) {
      callback(error, results.insertId);
    });
  });
}

SigClasses.prototype.lookup = function(classification, callback) {
  var self = this;
  
  if (!classification) {
    return callback("No classification provided");
  };

  if (self.sig_classes[classification.name]) {
    return callback(null, self.sig_classes[classification.name]);
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
      self.sig_classes[classification.name] = id;
      return callback(null, self.sig_classes[classification.name]);
    } 
  })
};

Signatures.prototype._load_cache = function() {
  var self = this;

  var query = 'select sig_id, sig_sid, sig_name, sig_gid, sig_rev from signature';

  var find = self.pool.query(query, function (error, results, fields) {
    if (!error) {

      for (var i in rows) {
        var sig = rows[i];
        var id =  sig.sig_sid 
        + "_" + sig.sig_gid 
        + "_" + sig.sig_rev 
        + "_" + sig.sig_name;  

        self.signatures[id] = sig.sig_id;
      }
   
      debug("loaded cache with signatures: ", i);
      self._cache_loaded = true;
    } else {
      console.error("error populating cache:", error)
    }
  });
}

Signatures.prototype._lookup_sigclass = function(event, callback) {
  var self = this;
  self.sigclasses.lookup(event.classification, callback);
};

Signatures.prototype._add_reference = function(reference, ref_seq, sig_id, callback) {
  var self = this;

  self.references.lookup(reference, function(error, ref_id) {
    if (error) {
      return callback(error); 
    }

    var query = self.db('insert into sig_reference (sig_id, ref_seq, ref_id)\
                         values (?, ?, ?) on duplicate key update sig_id = sig_id;');

    var params = [sig_id, ref_seq, ref_id];

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

  self._lookup_sigclass(event, function(error, sig_class_id) {

    var query = 'select sig_id from signature where \
    sig_sid = ? and sig_gid = ? and sig_rev = ? and sig_name = ?';

    var params = [ event.signature_id, event.generator_id, event.signature_revision,
    event.signature.name ];

    self.pool.query(query, params, function (error, results, fields) {
      if (error) {
        return callback(error);
      }

      var classification = results[0] || {};

      var sig_id = classification.sig_id;

      if (sig_id) {
        return callback(null, sig_id);
      }

      // otherwise, insert
      var query = 'insert into signature (sig_sid, sig_gid, \
      sig_class_id, sig_name, sig_priority, sig_rev) values (?,?,?,?,?,?) on duplicate key update sig_sid = sig_sid;';

      var params = [ event.signature_id, event.generator_id,
        sig_class_id,
        event.signature.name,
        event.classification.severity,
        event.signature_revision
      ];

      self.pool.query(query, params, function (error, results, fields) {
        if (error) {
          return callback(error);
        }

        var sig_id = results.insertId;

        var references = event.signature.references || [];
        var todo = references.length;
        var position = 0;

        var add = function() {
          position += 1;

          if (todo == 0) {
            return callback(error, sig_id);
          }

          todo--;

          var references = references.pop();

          self._add_reference(reference, position, sig_id, function(error) {
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

  self._fetch(event, function(error, sig) {
    debug("loading signature: ", sig);
    self.locked = false;
    if (error) {
      return callback(error); 
    } else {
      self.signatures[id] = sig;
      return callback(null, self.signatures[id]);
    } 
  });
};

module.exports = Signatures;