const config = require('config')
const router = require('express').Router()
const errors = require('utils/errors')
const logger = require('utils/logger').logger
const jwt    = require('jsonwebtoken')
const authenticator = require('authenticator')
const accountEventType = require('utils/account-logger').enumEventType

const Users = require('collections/users')


/**
 * AUTH COLLECTION
 */
router.post(  '/login',         authenticateBasic)
router.put(   '/verify/:token', verifyEmail)
router.post(  '/reset',         emailPasswordResetToken)
router.put(   '/reset/:token',  resetPassword)
router.post(  '/2fa',           prepare2FA)
router.post(  '/2fa/verify',    authenticate2FA)
router.delete('/2fa',           disable2FA)


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
        .then(result => handleAuthenticationResult(result, res, next, accountEventType.LOGIN_FAIL, accountEventType.LOGIN_SUCCESS))
        .catch(next)
}

/**
 * Verify the account's email address using a special JWT (query param) that was emailed to that email address
 * <- 204 / 400 / 404 / 500
 */
function verifyEmail(req, res, next) {
    const token = req.params.token
    // Check parameters (400)
    if (!token) {
        return next(errors.bad_request('No token was provided!'))
    }

    // Check token validity (400)
    jwt.verify(token, config.JWT_SECRET, (err, payload) => {
        if (err) return next(err)

        // Update password
        Users.updateById(payload.verify._id, { verified: true })
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
            const jwtData = { reset: { _id: user ? user._id : 'dummy' } }
            const jwtOptions = { expiresIn: config.JWT_PW_RESET_TIME }
            // Generate JWT (also if user is not found to not reveal that this email is not in use)
            jwt.sign(jwtData, config.JWT_SECRET, jwtOptions, (err, token) => {
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
    jwt.verify(token, config.JWT_SECRET, (err, payload) => {
        if (err) return next(err)

        // Update password
        Users.updateById(payload.reset._id, { password })
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
 * Prepare 2FA for a user to use with any TOTP mobile application
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
 * Verify 2FA using a 6-digit TOTP token for a certain user
 * This is also used to confirm the enabling of 2FA
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
            // Log enabling 2FA
            if (!req.user.use2FA && result.session.use2FA) {
                res.accountEvent = { userId: result.session._id, type: accountEventType._2FA_ENABLED }
            }
            handleAuthenticationResult(result, res, next, accountEventType._2FA_FAIL, accountEventType._2FA_SUCCESS)
        })
        .catch(next)
}

/**
 * Disable 2FA for a user
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
 * Handling a basic (email/password) or 2FA attempt is the same
 */
function handleAuthenticationResult(result, res, next, eventTypeFail, eventTypeSuccess) {
    // Setup account event log (fail=default)
    if (!res.accountEvent)
        res.accountEvent = { userId: result.session._id, type: eventTypeFail }

    // If the attempt failed to authenticate the account
    if (!result.authenticated)
        return next(errors.unauthorized())

    // Account was successfully authenticated: change account event type
    if (res.accountEvent.type === eventTypeFail)
        res.accountEvent.type = eventTypeSuccess

    // Create JWT asynchronousnly
    const jwtOptions = { expiresIn: config.JWT_EXPIRES_IN }
    jwt.sign(result.token, config.JWT_SECRET, jwtOptions, (err, token) => {
        if (err) return next(err)
        // Return new JWT
        res.status(200)
            .cookie('token', token, {
                httpOnly: true,
                sameSite: 'strict',
                path: config.API_PREFIX,
                secure: config.HTTPS_ENABLED,
                maxAge: config.JWT_EXPIRES_IN * 1000
            })
            // also pass token in body for non-web apps!
            // TODO: add header to identify the application and optionally return the token in the body
            .json({ session: result.session, token })
    })
}


module.exports = router
