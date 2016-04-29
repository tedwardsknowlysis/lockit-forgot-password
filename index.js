'use strict';

var path = require('path');
var events = require('events');
var util = require('util');
var express = require('express');
var uuid = require('node-uuid');
var pwd = require('couch-pwd');
var ms = require('ms');
var moment = require('moment');
var Mail = require('lockit-sendmail');

/**
 * Internal helper functions
 */
function join(view) {
  return path.join(__dirname, 'views', view);
}

/**
 * ForgotPassword constructor function.
 *
 * @param {Object} config
 * @param {Object} adapter
 */
var ForgotPassword = module.exports = function(config, adapter) {

  if (!(this instanceof ForgotPassword)) {return new ForgotPassword(config, adapter); }

  // call super constructor function
  events.EventEmitter.call(this);

  this.config = config;
  this.adapter = adapter;

  this.emailField = config.emailField ? config.emailField : 'email';
  this.nameField = config.nameField ? config.nameField : 'name';

  this.recoveryEmailField = config.recoveryEmailField ? config.recoveryEmailField : 'recoveryEmail';
  this.recoveryPhoneField = config.recoveryPhoneField ? config.recoveryPhoneField : 'recoveryPhone';
  this.recoveryField = config.recoveryField ? config.nameField : 'recoveryEmail';

  // set default route
  var route = config.forgotPassword.route || '/forgot-password';
  var routeLogin = config.forgotPassword.routeLogin || '/forgot-login';

  // add prefix when rest is active
  if (config.rest) {
    route = '/rest' + route;
    routeLogin = '/rest' + routeLogin;
  }

  /**
   * Routes
   */

  var router = new express.Router();
  router.get(route, this.getForgot.bind(this));
  router.post(route, this.postForgot.bind(this));
  router.post(routeLogin, this.postForgotLogin.bind(this));
  router.get(route + '/:token', this.getToken.bind(this));
  router.post(route + '/:token', this.postToken.bind(this));
  this.router = router;

};

util.inherits(ForgotPassword, events.EventEmitter);

/**
 * GET /forgot-password
 *
 * @param {Object} req
 * @param {Object} res
 * @param {Function} next
 */
ForgotPassword.prototype.getForgot = function(req, res, next) {
  var config = this.config;

  // do not handle the route when REST is active
  if (config.rest) {return next(); }

  // custom or built-in view
  var view = config.forgotPassword.views.forgotPassword || join('get-forgot-password');

  res.render(view, {
    title: 'Forgot password',
    basedir: req.app.get('views')
  });
};


/**
 * POST /forgot-password
 *
 * @param {Object} req
 * @param {Object} res
 * @param {Function} next
 */
ForgotPassword.prototype.postForgot = function(req, res, next) {
  var config = this.config;
  var adapter = this.adapter;
  var emailField = this.emailField;
  var nameField = this.nameField;
  var that = this;

  var email = req.body.email;

  var error = null;
  // regexp from https://github.com/angular/angular.js/blob/master/src/ng/directive/input.js#L4
  var EMAIL_REGEXP = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}$/;

  // check for valid input
  if (!email || !email.match(EMAIL_REGEXP)) {
    error = 'Email is invalid';

    // send only JSON when REST is active
    if (config.rest) {return res.json(403, {error: error}); }

    // custom or built-in view
    var errorView = config.forgotPassword.views.forgotPassword || join('get-forgot-password');

    res.status(403);
    return res.render(errorView, {
      title: 'Forgot password',
      error: error,
      basedir: req.app.get('views')
    });
  }

  // looks like given email address has the correct format

  // look for user in db
  adapter.find(emailField, email, function(err, user) {
    if (err) {return next(err); }

    // custom or built-in view
    var view = config.forgotPassword.views.sentEmail || join('post-forgot-password');

    // no user found -> pretend we sent an email
    if (!user) {
      // send only JSON when REST is active
      if (config.rest) {return res.send(204); }

      return res.render(view, {
        title: 'Forgot password',
        basedir: req.app.get('views')
      });
    }

    // user found in db
    // do not delete old password as it might be someone else
    // send link with setting new password page
    var token = uuid.v4();
    user.pwdResetToken = token;

    // set expiration date for password reset token
    var timespan = ms(config.forgotPassword.tokenExpiration);
    user.pwdResetTokenExpires = moment().add(timespan, 'ms').toDate();

    // update user in db
    adapter.update(user, function(er, usr) {
      if (er) {return next(er); }

      // send email with forgot password link
      var mail = new Mail(config);
      mail.forgot(usr[nameField], usr[emailField], token, function(e) {
        if (e) {return next(e); }

        // emit event
        that.emit('forgot::sent', usr, res);

        // send only JSON when REST is active
        if (config.rest) {return res.send(204); }

        res.render(view, {
          title: 'Forgot password',
          basedir: req.app.get('views')
        });
      });

    });

  });
};

/**
 * POST /forgot-login
 *
 * @param {Object} req
 * @param {Object} res
 * @param {Function} next
 */
ForgotPassword.prototype.postForgotLogin = function(req, res, next) {
  var config = this.config;
  var adapter = this.adapter;
  var emailField = this.emailField;
  var nameField = this.nameField;
  var recoveryEmailField = this.recoveryEmailField;
  var recoveryPhoneField = this.recoveryPhoneField;
  var recoveryField = this.recoveryField;
  var that = this;
  var error = null;

  var recoverySearchField = null,
    recoverySearch = null;
  if (req.body[recoveryEmailField]) {
    recoverySearchField = recoveryEmailField;
    recoverySearch = req.body[recoveryEmailField];
    var EMAIL_REGEXP = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}$/;
    // check for valid input
    if (!recoverySearch || !recoverySearch.match(EMAIL_REGEXP)) {
      error = 'Email is invalid';
    }
  } else if (req.body[recoveryPhoneField]) {
    recoverySearchField = recoveryPhoneField;
    recoverySearch = req.body[recoveryPhoneField];
    if (!recoverySearch) {
      error = 'Phone number is invalid!';
    }
  } else if (req.body[recoveryField]) {
    recoverySearchField = recoveryField;
    recoverySearch = req.body[recoveryField];
    if (!recoverySearch) {
      error = 'Recovery field is invalid!';
    }
  } else {
    error = 'No recovery method provided!';
  }

  // check for valid input
  if (error) {
    // send only JSON when REST is active
    if (config.rest) {return res.json(403, {error: error}); }

    // custom or built-in view
    var errorView = config.forgotPassword.views.forgotPassword || join('get-forgot-login');

    res.status(403);
    return res.render(errorView, {
      title: 'Forgot login',
      error: error,
      basedir: req.app.get('views')
    });
  }

  // TODO: If an email is provided as the method, then check if the email exists as a user...
  if (req.body[recoveryEmailField]) {
    adapter.find(emailField, recoverySearch, function(err, user) {
      if (user) {
        // send only JSON when REST is active
        var error = "Not a recovery email!";
        if (config.rest) {
          return res.json(403, {error: error});
        }

        res.status(403);
        return res.render(errorView, {
          title: 'Forgot login',
          error: error,
          basedir: req.app.get('views')
        });
      } else {
        findAndSendRecovery();
      }
    });
  } else {
    findAndSendRecovery();
  }

  function findAndSendRecovery() {
    // look for user in db
    adapter.find(recoverySearchField, recoverySearch, function (err, user) {
      if (err) {
        return next(err);
      }

      // custom or built-in view
      var view = config.forgotPassword.views.sentEmail || join('post-forgot-login');

      // no user found -> pretend we sent an email
      if (!user) {
        // send only JSON when REST is active
        if (config.rest) {
          return res.json(204, {message: 'No User with recovery: ' + recoverySearch});
        }

        return res.render(view, {
          title: 'Forgot Login',
          basedir: req.app.get('views')
        });
      }

      // If phone number used Text recovery...
      if (req.body[recoveryPhoneField]) {
        // emit event
        that.emit('forgot::text', user, recoverySearch, res);
        return res.json(204, {message: 'No User with recovery: ' + recoverySearch});
      }
      // TODO: If another method is used, figure out what to do there...?

      // If mail is recovery method, email a recover link?
      var mail = new Mail(config);
      mail.forgotLogin(user[nameField], recoverySearch, [user[emailField]], function (e) {
        if (e) {
          return next(e);
        }

        // emit event
        that.emit('forgotLogin::sent', user, res);

        // send only JSON when REST is active
        if (config.rest) {
          return res.json(200, {success: true, email: user[emailField]});
        }

        res.render(view, {
          title: 'Forgot login',
          basedir: req.app.get('views')
        });
      });
    });
  }
};

/**
 * GET /forgot-password/:token
 *
 * @param {Object} req
 * @param {Object} res
 * @param {Function} next
 */
ForgotPassword.prototype.getToken = function(req, res, next) {
  return this.handleToken(req, res, next);
};

/**
 * POST /forgot-password/:token
 *
 * @param {Object} req
 * @param {Object} res
 * @param {Function} next
 */
ForgotPassword.prototype.postToken = function(req, res, next) {
  var that = this;
  var password = req.body.password;
  var error = '';

  // check for valid input
  if (!password) {
    error = 'Please enter a password';

    // send only JSON when REST is active
    if (config.rest) {return res.json(403, {error: error}); }

    // custom or built-in view
    var view = config.forgotPassword.views.forgotPassword || join('get-forgot-password');

    res.status(403);
    return res.render(view, {
      title: 'Choose a new password',
      error: error,
      token: token,
      basedir: req.app.get('views')
    });
  }

  return this.handleToken(req, res, next, password);
};

ForgotPassword.prototype.handleToken = function(req, res, next, password) {
  var config = this.config;
  var adapter = this.adapter;

  // get token
  var token = req.params.token;

  // verify format of token
  var re = new RegExp('[0-9a-f]{22}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'i');

  // if format is wrong no need to query the database
  if (!re.test(token)) {return next(); }

  // check for token in db
  adapter.find('pwdResetToken', token, function(err, user) {
    if (err) {return next(err); }

    // if no token is found forward to error handling middleware
    if (!user) {return next(); }

    // check if token has expired
    if (new Date(user.pwdResetTokenExpires) < new Date()) {
      // make old token invalid
      delete user.pwdResetToken;
      delete user.pwdResetTokenExpires;

      // update user in db
      return adapter.update(user, function(e) {
        if (e) {return next(e); }

        // send only JSON when REST is active
        if (config.rest) {return res.json(403, {error: 'link expired'}); }

        // custom or built-in view
        var viewExpired = config.forgotPassword.views.linkExpired || join('link-expired');

        // tell user that link has expired
        res.render(viewExpired, {
          title: 'Forgot password - Link expired',
          basedir: req.app.get('views')
        });
      });
    }

    if (!password) {
      // send only JSON when REST is active
      if (config.rest) {return res.send(204); }

      // custom or built-in view
      var view = config.forgotPassword.views.newPassword || join('get-new-password');

      // render success message
      return res.render(view, {
        token: token,
        title: 'Choose a new password',
        basedir: req.app.get('views')
      });
    }
    else {
      // if user comes from couchdb it has an 'iterations' key
      if (user.iterations) {
        pwd.iterations(user.iterations);
      }

      // create hash for new password
      pwd.hash(password, function (hashError, salt, hash) {
        if (hashError) {
          return next(hashError);
        }

        // update user's credentials
        user.salt = salt;
        user.derived_key = hash; // eslint-disable-line camelcase

        // remove helper properties
        delete user.pwdResetToken;
        delete user.pwdResetTokenExpires;

        // update user in db
        adapter.update(user, function (updateErr, updateUser) {
          if (updateErr) {
            return next(updateErr);
          }

          // emit event
          that.emit('forgot::success', updateUser, res);

          // send only JSON when REST is active
          if (config.rest) {
            return res.send(204);
          }

          // custom or built-in view
          var viewChanged = config.forgotPassword.views.changedPassword || join('change-password-success');

          // render success message
          return res.render(viewChanged, {
            title: 'Password changed',
            basedir: req.app.get('views')
          });
        });
      });
    }
  });
};
