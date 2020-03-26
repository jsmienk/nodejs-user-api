'use strict'

const config = require('config')
const router = require('express').Router()
const errors = require('utils/errors')
const logger = require('utils/logger').logger
const jwtAuth = require('utils/jwt')
const useragent = require('express-useragent')
const authenticator = require('authenticator')
const accountEventType = require('utils/account-logger').enumEventType

const Users = require('collections/users')


/**
 * AUTH COLLECTION
 */
router.post(  '/login',         useragent.express(), authenticateBasic)
router.post(  '/logout',                             logout)
router.put(   '/verify/:token',                      verifyEmail)
router.post(  '/reset',                              emailPasswordResetToken)
router.put(   '/reset/:token',                       resetPassword)
router.post(  '/2fa',                                prepare2FA)
router.post(  '/2fa/verify',    useragent.express(), authenticate2FA)
router.delete('/2fa',                                disable2FA)


/**
 * Authenticate a specific user by its id provided as query parameter
 * @body email, password
 * <- 200 / 400 / 401 / 500
 */
function authenticateBasic(req, res, next) {
    const email = req.body.email
    const password = req.body.password
    // Check parameters (400)
    if (!email || !password) {
        return next(errors.bad_request('No email and password was provided!'))
    }

    Users.authenticateBasic(email, password)
        .then(result => handleAuthResult(result, req, res, next, accountEventType.LOGIN_FAIL, accountEventType.LOGIN_SUCCESS))
        .catch(next)
}

/**
 * Logout by clearing token session cookies
 */
function logout(_, res, __) {
    jwtAuth.clearCookies(res).status(204).send()
}

/**
 * Verify the account's email address using a special JWT (query param) that was emailed to that email address
 * <- 204 / 400 / 404 / 500
 */
function verifyEmail(req, res, next) {
    const token = req.params.token
    // Check parameters (400)
    if (!token)
        return next(errors.bad_request('No token was provided!'))

    // Check token validity (400)
    jwtAuth.verify(token, (err, payload) => {
        if (err) return next(err)
        // Update password
        Users.updateById(payload.verify, { verified: true })
            .then(user => {
                if (!user) return next(errors.not_found())
                // Log email verification
                res.accountEvent = { userId: user._id, type: accountEventType.EMAIL_VERIFIED }
                res.status(204).send()
            })
            .catch(next)
    })
}

/**
 * Request a password reset email
 * This method will also return 204 if the email is not a user, to hide the usage of email addresses
 * <- 204 / 400 / 500
 */
function emailPasswordResetToken(req, res, next) {
    const email = req.body.email
    const link = req.body.link
    // Check parameter (400)
    if (!email || !link) {
        return next(errors.bad_request('Email address or callback link was not provided!'))
    }

    // Find user
    Users.findByEmail(email)
        .then(user => {
            // Generate JWT (also if user is not found to not reveal that this email is not in use)
            jwtAuth.signEmailToken({ reset: user ? user._id : 'dummy' }, (err, token) => {
                if (err) return next(err)
                // Email only if the email is used by a user
                if (user) {
                    // Log password reset request
                    res.accountEvent = { userId: user._id, type: accountEventType.RESET_REQUEST }

                    const resetLink = link + token
                    logger.debug('Reset link:\n' + resetLink)

                    // Email the user a reset email
                    // TODO

                    logger.info('Password reset email sent to "' + user._id + '".')
                }
                res.status(204).send()
            })
        })
        .catch(next)
}

/**
 * Reset the password using a special JWT (query param) and a new password (body)
 * <- 204 / 400 / 404 / 500
 * 
 * TODO: revoke device sessions!
 */
function resetPassword(req, res, next) {
    const token = req.params.token
    const password = req.body.password
    // Check parameters (400)
    if (!token || !password) {
        return next(errors.bad_request('No token and new password were provided!'))
    }
    // Check password length (400)
    if (password && password.length < config.MIN_PASS_LENGTH) {
        return next(errors.bad_request('Password must be at least ' + config.MIN_PASS_LENGTH + ' characters long!'))
    }

    // Check token validity (400)
    jwtAuth.verify(token, (err, payload) => {
        if (err) return next(err)
        // Update password
        Users.updateById(payload.reset, { password })
            .then(user => {
                if (!user) return next(errors.not_found())
                // Log password reset
                res.accountEvent = { userId: user._id, type: accountEventType.RESET_SUCCESS }
                res.status(204).send()
            })
            .catch(next)
    })
}

/**
 * Prepare 2FA  for the authenticated user to use with any TOTP mobile application
 * <- 201 / 401 / 404 / 500
 */
function prepare2FA(req, res, next) {
    const key2FA = authenticator.generateKey()
    Users.updateById(req.user._id, { key2FA, use2FA: false })
        .then(user => {
            logger.debug(user)
            if (!user) return next(errors.not_found())
            // Log 2FA prepared
            res.accountEvent = { userId: user._id, type: accountEventType._2FA_PREPARED }
            // Generate and return TOTP application registration QR string
            const registration = authenticator.generateTotpUri(key2FA, user.email, config.APP_NAME, 'SHA1', 6, 30)
            res.status(201).send({ registration })
        })
        .catch(next)
}

/**
 * Verify 2FA using a 6-digit TOTP token for the authenticated user
 * This is *also* used to confirm the enabling of 2FA
 * <- 200 / 400 / 401 / 404 / 500
 */
function authenticate2FA(req, res, next) {
    const token = req.body.token
    // Check parameters (400)
    if (!token) {
        return next(errors.bad_request('No token was provided!'))
    }

    Users.authenticate2FA(req.user._id, token)
        .then(result => {
            // If this request was to enable 2FA. log the enabling 2FA,
            if (!req.user.use2FA && result.session.use2FA)
                res.accountEvent = { userId: result.session._id, type: accountEventType._2FA_ENABLED }
                handleAuthResult(result, req, res, next, accountEventType._2FA_FAIL, accountEventType._2FA_SUCCESS)
        })
        .catch(next)
}

/**
 * Disable 2FA for the authenticated user
 * <- 204 / 401 / 404 / 500
 */
function disable2FA(req, res, next) {
    Users.updateById(req.user._id, { use2FA: false })
        .then(user => {
            if (!user) return next(errors.not_found())
            // Log 2FA disabled
            res.accountEvent = { userId: user._id, type: accountEventType._2FA_DISABLED }
            res.status(204).send()
        })
        .catch(next)
}


// HELPERS

/**
 * Authentication result helper
 * Because handling a basic (email/password) or 2FA authentication attempt is the same
 * @param result { user: Object, payload: Object, authenticated: Boolean }
 */
function handleAuthResult(result, req, res, next, eventTypeFail, eventTypeSuccess) {
    // If the attempt failed to authenticate the account
    if (!result.authenticated) {
        // Log fail
        res.accountEvent = { userId: result.user._id, type: eventTypeFail }
        return next(errors.unauthorized())
    }
    // Log success
    if (!res.accountEvent)
        res.accountEvent = { userId: result.user._id, type: eventTypeSuccess }

    // Create token JWT asynchronousnly
    jwtAuth.signToken(result.payload, (err, token) => {
        if (err) return next(err)
        // Initialize session
        const client = { ip: req.ip, useragent: req.useragent }
        Users.initSession(result.user._id, req.cookies[jwtAuth.COOKIE_SESSION], client)
            .then(sid => {
                // Return access token JWT
                res.status(200).cookie(jwtAuth.COOKIE_TOKEN, token, jwtAuth.COOKIE_TOKEN_OPTIONS)
                // Return session ID JWT if the user does not use 2FA or they passed 2FA
                if (!result.user.use2FA || (result.user.use2FA && result.user.passed2FA))
                    res.cookie(jwtAuth.COOKIE_SESSION, sid, jwtAuth.COOKIE_SESSION_OPTIONS)
                // TODO: add header to identify the application and optionally return the token in the body
                // TODO: also pass tokens in body for non-web apps!
                res.json({ user: result.user, expiresIn: config.SESSION_EXPIRES_IN * 1000 })
            })
            .catch(next)
    })
}


module.exports = router
