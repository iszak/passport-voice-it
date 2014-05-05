/**
 * Module dependencies.
 */
var util = require('util');

var passport = require('passport-strategy'),
    lookup = require('./utils').lookup;

var voiceIt = require('voice-it')();

var dataUriToBuffer = require('data-uri-to-buffer');

/**
 * `Strategy` constructor.
 *
 * The voice it authentication strategy authenticates requests based on the
 * credentials submitted through an HTML-based login form.
 *
 * Applications must supply a `verify` callback which accepts `email`,
 * `password` and `wav` credentials, and then calls the `done` callback supplying a
 * `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occured, `err` should be set.
 *
 * Optionally, `options` can be used to change the fields in which the
 * credentials are found.
 *
 * Options:
 *   - `emailField`    field name where the email is found, defaults to _email_
 *   - `passwordField` field name where the password is found, defaults to _password_
 *   - `wavField`      field name where the password is found, defaults to _wav_
 *
 *   - `developerId`           voice it developer id
 *   - `accuracy`              voice it accuracy where 0 is strict to 5 which is lax
 *   - `accuracyPasses`        voice it accuracy passes from 1 to 10
 *   - `accuracyPassIncrement` voice it accuracy pass increment from 1 to 5
 *   - `confidence`            voice it confidence from 85 to 100
 *
 *   - `badRequestMessage` message to display when any credentials, defaults to _Missing credentials_
 * Examples:
 *
 *     passport.use(new wavStrategy(
 *       function(email, password, wav, done) {
 *         User.findOne({ email: email }, function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  if (!options.developerId) {
    throw new TypeError('VoiceItStrategy requires a developer ID');
  }

  if (!verify) {
    throw new TypeError('VoiceItStrategy requires a verify callback');
  }

  this._developerId           = options.developerId;
  this._accuracy              = options.accuracy || 0;
  this._accuracyPasses        = options.accuracyPasses || 5;
  this._accuracyPassIncrement = options.accuracyPassIncrement || 2;
  this._confidence            = options.confidence || 85;

  this._emailField    = options.emailField    || 'email';
  this._passwordField = options.passwordField || 'password';
  this._wavField      = options.wavField      || 'wav';

  passport.Strategy.call(this);

  this.name    = 'voice-it';
  this._verify = verify;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};

  var email    = lookup(req.body, this._emailField) || lookup(req.query, this._emailField);
  var password = lookup(req.body, this._passwordField) || lookup(req.query, this._passwordField);
  var wav      = lookup(req.body, this._wavField) || lookup(req.query, this._wavField);

  if (!email || !password || !wav) {
    return this.fail({ message: options.badRequestMessage || 'Missing credentials' }, 400);
  }

  var self = this;

  function verified(err, user, info) {
    if (err) {
      return self.error(err);
    }

    if (!user) {
      return self.fail(info);
    }

    self.success(user, info);
  }

  try {
    var promise = voiceIt.Authentication.authentication({
      email: email,
      password: password,
      wav: dataUriToBuffer(wav),

      developerId: this._developerId,
      accuracy: this._accuracy,
      accuracyPasses: this._accuracyPasses,
      accuracyPassIncrement: this._accuracyPassIncrement,
      confidence: this._confidence
    });

    promise.then(function() {
      self._verify(email, password, wav, verified);
    }).catch(self.fail);
  } catch (ex) {
    self.error({
      message: ex.message
    });
  }
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
