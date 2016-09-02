/**
 * Module dependencies.
 */
var util = require('util')
    , OAuthStrategy = require('passport-oauth').OAuthStrategy
    , InternalOAuthError = require('passport-oauth').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * The Atlassian Oauth authentication strategy authenticates requests by delegating to
 * an Atlassian application using the OAuth 1.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts a `token`,
 * `tokenSecret` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occurred, `err` should be set.
 * 
 * Options:
 *   - `applicationURL` your Atlassian application URL
 *   - `consumerKey`  the OAuth consumer key configured in application links in your Atlassian application
 *   - `consumerSecret`  the RSA private key used to sign OAuth requests.  The Atlassian apps OAuth public key must match
 *
 * Examples:
 *
 *     passport.use(new AtlassianOAuthStrategy({
 *         applicationURL:"http://jira.atlassian.com",
 *         consumerKey:"sample-nodejs-app",
 *         consumerSecret:"<RSA-PRIVATE-KEY PEM encoded>",
 *       },
 *       function(token, tokenSecret, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
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
    options = options || {};
    if (!options.applicationURL)  throw new Error('Atlassian Oauth Strategy requires a applicationURL option');
    if (!options.callbackURL)  throw new Error('Atlassian Oauth Strategy requires a callbackURL option');

    options.requestTokenURL = options.requestTokenURL || options.applicationURL + '/plugins/servlet/oauth/request-token';
    options.accessTokenURL = options.accessTokenURL || options.applicationURL + '/plugins/servlet/oauth/access-token';
    options.userAuthorizationURL = options.userAuthorizationURL || options.applicationURL + '/plugins/servlet/oauth/authorize';
    options.signatureMethod = options.signatureMethod || "RSA-SHA1";

    OAuthStrategy.call(this, options, verify);
    this.name = 'atlassian-oauth';
    this._applicationURL = options.applicationURL;
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuthStrategy);


/**
 * Retrieve user profile from the Atlassian Application.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `atlassian-oauth`
 *   - `id`               the user's username
 *   - `username`         the user's username
 *   - `displayName`      the user's full name
 *   - `avatarUrls`      the user's avatar URLs for different sized avatar images provided by the Atlassian app
 *   - `timeZone`       the user's timezone
 *   - `emails`           the proxied or contact email address granted by the user
 *   - `groups`         the user's group memberhips
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function (token, tokenSecret, params, done) {
    var self = this;
    try {
        var stashWhoAMIResource = self._applicationURL + "/plugins/servlet/applinks/whoami";
        self._oauth._performSecureRequest(token, tokenSecret, "GET", stashWhoAMIResource, null, "", "application/json", function (err, body, res) {
            if (err) {
                return done(new InternalOAuthError('failed to fetch username', err));
            }

            var username = body;
            var stashProfileResource = self._applicationURL + "/rest/api/1.0/users/" + username;

            try {
                self._oauth._performSecureRequest(token, tokenSecret, "GET", stashProfileResource, null, "", "application/json", function (err, body, res) {
                    if (err) {
                        return done(new InternalOAuthError('failed to fetch user profile', err));
                    }

                    var json = JSON.parse(body);
                    var profile = { provider:'atlassian-oauth' };
                    profile.id = json.name;
                    profile.username = json.name;
                    profile.displayName = json.displayName;
                    profile.avatarUrls = json.slug;
                    profile.emails = [
                        { value:json.emailAddress }
                    ];

                    profile._raw = body;
                    profile._json = json;
                    profile.token = token;
                    profile.tokenSecret = tokenSecret;
                    done(null, profile);
                });
            } catch (e) {
                done(e);
            }
        });
    } catch (e) {
        done(e);
    }
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
