'use strict'

const config = require('config')
const errors = require('utils/errors')
const logger = require('utils/logger').logger
const jwtAuth = require('utils/jwt')
const bcrypt = require('bcryptjs')
const authenticator = require('authenticator')
const getLocation = require('utils/geolocation')

const DeviceSession = require('collections/models/device-session')
const AccountLog = require('collections/models/account-log')
const User = require('collections/models/user')

/**
 * Operations:
 * - authenticate
 * - get all users
 * - get user by id
 * - create new user
 * - update user by id
 * - remove user by id
 */
module.exports = {
    authenticateBasic,
    authenticate2FA,
    getAll,
    getById,
    create,
    updateById,
    removeById,
    findByEmail,
    initSession,
    getSessionById,
    logEvent
}

const SELECT_SENSITIVE = '+email +use2FA +verified'
const SELECT_SENSITIVE_ALL = SELECT_SENSITIVE + ' +key2FA'

/**
 * Authenticate a specific user using a provided email and password
 * @returns result { user: Object, payload: Object, sessions: Map, authenticated: Boolean }
 */
async function authenticateBasic(provided_email, password) {
    // Explicitly ask for hash because selection is disabled in the model
    const user = await User.findOne({ email: provided_email }).select(SELECT_SENSITIVE_ALL + ' +hash')
    if (!user) {
        // Compare 'nope' to 'password' to imitatie the time it takes if the user was found
        // The request duration no longer shows if an email address is in use
        await bcrypt.compare('nope', '$2a$10$iAHu4zy8AlLsuz/GkuVuoutr9uNXvKiWf33xtZn7XeX67vmntsn9e')
        throw errors.unauthorized()
    }

    const authenticated = await bcrypt.compare(password, user.hash)
    // If we failed
    if (!authenticated)
        return { user: { _id: user._id }, authenticated }

    return { ...jwtAuth.separateUser(user, false), authenticated }
}

/**
 * Authenticate 2FA for a specific user using a TOTP 6-digit token
 * key === null and use === false  means 2FA disabled
 * key !== null and use === false  means 2FA prepared
 * key !== null and use === true   means 2FA enabled
 * @returns result { user: Object, payload: Object, sessions: Map, authenticated: Boolean }
 */
async function authenticate2FA(id, totp) {
    // Explicitly ask for 2FA key because selection is disabled in the model
    let user = await User.findById(id).select(SELECT_SENSITIVE)
    // If the user cannot be found
    if (!user) throw errors.not_found()

    // If the user does not use 2FA, do not reveal it is disabled
    if (!user.key2FA) throw errors.unauthorized()

    const authenticated = authenticator.verifyToken(user.key2FA, totp) !== null
    // If we failed
    if (!authenticated)
        return { user: { _id: user._id }, authenticated }

    // 2FA preparation success if use was disabled but the authentication succeeded
    if (!user.use2FA && authenticated) {
        // Enable 2FA
        user = await updateById(id, { use2FA: true })
    }

    return { ...jwtAuth.separateUser(user, authenticated), authenticated }
}

/**
 * Get all users from the database
 * Does not return the users' hashed passwords
 */
async function getAll() {
    return User.find().select('-__v')
}

/**
 * Get a specific user from the databases using its MongoDB ObjectId
 * Does not return the user's log and hashed password
 */
async function getById(id, sensitive=false) {
    const query = User.findById(id).select('-__v')
    if (sensitive)  query.select(SELECT_SENSITIVE)
    return query
}

/**
 * Create a new user using an email, name, and plain-text password
 * The password is hashed using bcrypt before insertion
 */
async function create(email, name, password, meta={}) {
    // Hash user password (with salt)
    const hash = await bcrypt.hash(password, config.BCRYPT_ROUNDS)
    return new User({ email, name, hash, meta }).save()
}

/**
 * Update an existing user using an email, and/or name, and/or plain-text password
 * The password is hashed using bcrypt before updating
 * Verified is false again if an email is provided
 * Disabled 2FA removes the TOTP key
 */
async function updateById(id, params) {
    const update = {}
    //  route param      MongoDB field     value
    if (params.email)    update.email    = params.email
    if (params.name)     update.name     = params.name
    if (params.password) update.hash     = await bcrypt.hash(params.password, config.BCRYPT_ROUNDS)
    if (params.verified) update.verified = true
    if (params.email)    update.verified = false
    if (params.key2FA)   update.key2FA   = params.key2FA
    if (params.use2FA)   update.use2FA   = true

    if (params.use2FA === false) update.use2FA = false

    return User.findByIdAndUpdate(id, update, { upsert: false, runValidators: true })
}

/**
 * Delete an existing user using its MongoDB ObjectId
 */
async function removeById(user) {
    await DeviceSession.deleteMany({ user })
    await AccountLog.deleteMany({ user })
    return User.findByIdAndRemove(user)
}

/**
 * Get a specific user from the databases using its email
 * Does not return the user's log and hashed password
 */
async function findByEmail(email) {
    return User.findOne({ email })
}

/**
 * Start or update a device session
 * @param id user id
 * @param sid session id | null
 * @param client { ip: string, useragent: object }
 */
async function initSession(id, sid, client) {
    // Format client details
    const ip = client.ip
    const expires = Date.now() + config.SESSION_EXPIRES_IN * 1000
    let location
    try { location = await getLocation(ip) } catch (_) {}
    const platform = client.useragent.os
    const application = `${client.useragent.browser} (${client.useragent.version})`

    let session
    let sessionID = sid
    try {
        // Find existing session
        session = await getSessionById(sid)
        session.since = new Date()
        session.ip = ip
        session.expires = expires
        session.location = location
        session.platform = platform
        session.application = application
    } catch (_) {
        // Create a new one
        sessionID = jwtAuth.getNewSID()
        session = new DeviceSession({ 
            hash: jwtAuth.getSIDHash(sessionID),
            user: id, ip, expires, location, platform, application
        })
    }
    // Save session
    await session.save()
    // Return unhashed session id
    return sessionID
}

/**
 * Get a session by its session id
 * @param sid session id
 */
async function getSessionById(sid, popUser=false) {
    const query = DeviceSession.find({ hash: jwtAuth.getSIDHash(sid) })
    if (popUser)
        query.populate({ path: 'user', select: SELECT_SENSITIVE_ALL })
    const sessions = await query
    if (sessions.length === 0)
        throw errors.not_found('Session is not found!')
    return sessions[0]
}

/**
 * Log an account related event
 * @param user user id
 * @param ip client IP address (string)
 * @param type account event type as defined by that module (utils/account-logger)
 */
async function logEvent(user, ip, type) {
    let location
    try { location = await getLocation(ip) } catch (ignore) {}
    return new AccountLog({ user, ip, type, location }).save()
}
