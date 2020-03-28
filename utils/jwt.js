'use strict'

/**
 * Responsible for everything JWT related:
 * - Access and session tokens
 * - Signing tokens
 * - Verifying token
 * - Token cookies
 * - Verification middleware
 * - Session middleware
 */

const config = require('config')
const errors = require('utils/errors')
const logger = require('utils/logger').logger
const expressJWT = require('express-jwt')
const crypto = require('crypto')
const jwt = require('jsonwebtoken')

const Users = require('collections/users')


// SIGNING / VERIFICATION WRAPPERS

exports.verify = (token, callback) => {
    jwt.verify(token, config.JWT_SECRET, { algorithms: config.JWT_ALG }, callback)
}

exports.signToken = (payload, callback) => {
    const options = { expiresIn: config.JWT_EXPIRES_IN, algorithm: config.JWT_ALG }
    jwt.sign(payload, config.JWT_SECRET, options, callback)
}

exports.signEmailToken = (payload, callback) => {
    const options = { expiresIn: config.JWT_EMAIL_TIME, algorithm: config.JWT_ALG }
    jwt.sign(payload, config.JWT_SECRET, options, callback)
}

// ACCESS VERIFICATION HANDLER

exports.verificationHandler = expressJWT({ secret: config.JWT_SECRET, algorithms: config.JWT_ALGS, getToken, isRevoked }).unless({
    path: [
        // Routes that don't require authentication
        { methods: ['POST'], url: config.API_PREFIX + '/users' },  // Register
        { methods: ['POST'], url: config.API_PREFIX + '/auth/login' },  // Login
        { methods: ['POST'], url: config.API_PREFIX + '/auth/reset' },  // Request password reset
        { methods: ['PUT'], url: new RegExp(config.API_PREFIX + '/auth/reset/[a-zA-Z._]+', 'g') },  // Reset password
        { methods: ['PUT'], url: new RegExp(config.API_PREFIX + '/auth/verify/[a-zA-Z._]+', 'g') },  // Verify email
    ]
})

function getToken (req) {
    // 1. Token from cookie
    if (req.cookies[exports.COOKIE_TOKEN])
        return req.cookies[exports.COOKIE_TOKEN]
    // 2. Token from header
    if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer')
        return req.headers.authorization.split(' ')[1]
    // No token found in request
    return null
}

async function isRevoked(req, payload, done) {
    // Do no revoke token if user is trying to pass 2FA
    if (req.path === config.API_PREFIX + '/auth/2fa/verify' ||
        req.path === config.API_PREFIX + '/auth/2fa/verify/')
        return done()
    // Revoke token if user did not pass 2FA (if enabled)
    if (payload.use2FA && !payload.passed2FA)
        return done('Client has not passed 2FA yet!', true)
    done()
}

// SESSION VERIFICATION HANDLER

/**
 * To be used directly after the verification handler.
 * Tries to refresh an expired token JWT if a valid session JWT is provided
 */
exports.refreshHandler = (err1, req, res, next) => {
    const anonError = errors.unauthorized('No valid access token or session ID provided!')
    const sid = req.cookies[exports.COOKIE_SESSION]
    // If the access token has expired, then we may use a valid session id JWT to grant a new access JWT
    if (!!sid) {
        logger.info('\n  REFRESHING TOKEN')
        Users.getSessionById(sid, true)
            .then(session => {
                // Check expiration time
                if (session.expires < Date.now()) {
                    // Remove session if expired
                    Users.revokeSession(session.hash).catch(console.warn)
                    return next(anonError)
                }
                // If not expired, generate new token JWT
                const contents = exports.separateUser(session.user, true)
                exports.signToken(contents.payload, (err2, token) => {
                    if (err2) return next(anonError)
                    // Update cookie
                    res.cookie(exports.COOKIE_TOKEN, token, exports.COOKIE_TOKEN_OPTIONS)
                    // Save payload like a successful verification would do
                    req.user = contents.user
                    // Keep going as if we were authenticated
                    next()
                })
            })
            .catch(err3 => {
                logger.warn(err3)
                next(anonError)
            })
    } else next(err1)
}

exports.getNewSID = () => {
    // using regex to make it URL safe
    return crypto.randomBytes(64).toString('base64').replace(/\//g,'_').replace(/\+/g,'.').replace(/\=/g,'-')
}

exports.getSIDHash = (sid) => {
    return crypto.createHash('sha256').update(sid).digest('base64')
}

/**
* Helper to create a token content and user object from an authenticated user
* @param user
* @param passed2FA
* @returns object { payload, user }
*/
exports.separateUser = (_user, passed2FA=false) => {
   // Specify inclusion criteria to exclude new fields by default!
   const { _id, meta, email, name, use2FA, creation, verified } = _user.toObject()
   // Only return non-sensitive information in the token payload
   const payload = { _id, verified, use2FA, passed2FA }
   const user = { ...payload }
   // Add more sensitive information if this is the end of the auth flow
   if (!use2FA || (use2FA && passed2FA)) {
       user.meta = meta
       user.email = email
       user.name = name
       user.creation = creation
   }
   return { payload, user }
}

// COOKIES

const COOKIE_OPTIONS = {
    httpOnly: true,
    sameSite: 'Strict',
    path: config.API_PREFIX,
    secure: config.HTTPS_ENABLED
}
exports.COOKIE_TOKEN = 'token'
exports.COOKIE_TOKEN_OPTIONS = {
    ...COOKIE_OPTIONS,
    maxAge: config.JWT_EXPIRES_IN * 1000
}
exports.COOKIE_SESSION = 'session'
exports.COOKIE_SESSION_OPTIONS = {
    ...COOKIE_OPTIONS,
    maxAge: config.SESSION_EXPIRES_IN * 1000
}

exports.clearCookies = (res) => {
    return res
        .clearCookie(exports.COOKIE_TOKEN, exports.COOKIE_TOKEN_OPTIONS)
        .clearCookie(exports.COOKIE_SESSION, exports.COOKIE_SESSION_OPTIONS)
}
