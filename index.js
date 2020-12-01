var async = require('async');
var errors = require('errors');
var _ = require('lodash');

var sera = require('../index');

var format = function () {
  return util.format.apply(util.format, Array.prototype.slice.call(arguments));
};

var unprocessableEntity = function () {
  var message = format.apply(format, Array.prototype.slice.call(arguments));
  return errors.unprocessableEntity(message);
};

exports.password = {
  validator: function (options) {
    options = options || {};

    var block = function (o, done) {
      if (!options.block) {
        return done(null, {});
      }
      options.block(o, done);
    };

    return function (o, done) {
      block(o, function (err, blocked) {
        if (err) {
          return done(err);
        }

        var password = o.value;
        var field = options.field || o.field;
        if (!password) {
          return done(unprocessableEntity('\'%s\' needs to be specified', field));
        }
        if (password.length < 6) {
          return done(unprocessableEntity('\'%s\' should at least be 6 characters', field));
        }
        var pass = password.toLowerCase();
        var name;
        for (name in blocked) {
          if (!blocked.hasOwnProperty(name)) {
            continue;
          }
          if (pass !== blocked[name].toLowerCase()) {
            continue;
          }
          return done(unprocessableEntity('\'%s\' should not be equivalent to the \'%s\'', field, name));
        }
        if (!/[0-9]/.test(password)) {
          return done(unprocessableEntity('\'%s\' should contain at least one number', field));
        }
        if (!/[a-z]/.test(password)) {
          return done(unprocessableEntity('\'%s\' should contain at one lower case letter', field));
        }
        if (!/[A-Z]/.test(password)) {
          return done(unprocessableEntity('\'%s\' should contain at one upper case letter', field));
        }
        if (!/[`~!@#$%^&*()\-_=+[{\]}\\|;:'",<.>/?\s]/.test(password)) {
          return done(unprocessableEntity('\'%s\' should contain at one special character', field));
        }
        done(null, password);
      });
    };
  },
  value: null
};

exports.email = {
  validator: function (options) {
    options = options || {};
    return function (o, done) {
      var email = o.value;
      var field = options.field || o.field;
      if (!email) {
        return done(unprocessableEntity('\'%s\' needs to be specified', field));
      }
      var at = email.indexOf('@');
      var dot = email.lastIndexOf('.');
      if (at === -1 || dot === -1 || dot < at) {
        return done(unprocessableEntity('\'%s\' needs to be a valid email address', field));
      }
      done(null, email);
    };
  }
};

exports.groups = {
  validator: function (options) {
    options = options || {};
    return function (o, done) {
      var groups = o.value;
      var field = options.field || o.field;
      var max = o.options.max || options.max || 10;
      var min = o.options.min || options.min || 0;
      if (!groups) {
        return done(unprocessableEntity('\'%s\' needs to be specified', field));
      }
      if (!Array.isArray(groups)) {
        return done(unprocessableEntity('\'%s\' needs to be an array', field));
      }
      if (max < groups.length) {
        return done(unprocessableEntity('\'%s\' exceeds the allowed length', field));
      }
      if (min > groups.length) {
        return done(unprocessableEntity('\'%s\' needs to contain more values', field));
      }
      async.each(groups, function (v, validated) {
        var validator = exports.ref();
        validator({
          user: o.user,
          path: o.path,
          field: field + '[*]',
          value: v,
          options: o.options
        }, validated);
      }, function (err) {
        if (err) {
          return done(err);
        }
        var Groups = sera.model('groups');
        var query = {_id: {$in: groups}};
        commons.permitOnly({user: o.user}, query, {$in: ['*', 'read']}, function (err) {
          if (err) {
            return done(err);
          }
          Groups.find(query).select('_id').exec(function (err, groupz) {
            if (err) {
              return done(err);
            }
            if (!groupz || (groups.length !== groupz.length)) {
              return done(unprocessableEntity('\'%s\' contains invalid values', field));
            }
            done(null, groups);
          });
        });
      });
    };
  },
  value: function (options) {
    options = options || {};
    return function (o, done) {
      sera.group('public', function (err, pub) {
        if (err) {
          return done(err);
        }
        done(null, [pub.id]);
      });
    };
  }
};

exports.username = {
  validator: function (options) {
    options = options || {};
    return function (o, done) {
      return exports.string(options)(o, function (err) {
        if (err) {
          return done(err);
        }
        var value = o.value;
        var field = options.field || o.field;
        var regex = '^([a-z0-9]{1}[a-z0-9\\-]{0,' + (options.length - 2) + '}[a-z0-9]{1}|[a-z0-9]){1}$';
        if (/^.*(-)\1{1,}.*$/.test(value) || !RegExp(regex).test(value)) {
          return done(unprocessableEntity('\'%s\' contains an invalid value', field));
        }
        done(null, value);
      });
    };
  }
};