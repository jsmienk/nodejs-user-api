const config = require('config')
const errors = require('utils/errors')
const logger = require('utils/logger').logger
const bcrypt = require('bcryptjs')
const authenticator = require('authenticator')

const User = require('collections/models/user')
const AccountLog = require('collections/models/account-log')

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
    logEvent
}

/**
 * Authenticate a specific user using a provided email and password
 */
async function authenticateBasic(provided_email, password) {
    // Explicitly ask for hash because selection is disabled in the model
    const user = await User.findOne({ email: provided_email }).select('+email +hash')
    if (!user) {
        // Compare 'nope' to 'password' to imitatie the time it takes if the user was found
        // The request duration no longer shows if an email address is in use
        await bcrypt.compare('nope', '$2a$10$iAHu4zy8AlLsuz/GkuVuoutr9uNXvKiWf33xtZn7XeX67vmntsn9e')
        throw errors.unauthorized()
    }

    // Specify inclusion criteria to exclude new fields by default!
    const { _id, meta, email, name, use2FA, creation, verified, hash } = user.toObject()

    // Only return non-sensitive information in the taken payload
    const token = {
        _id,
        verified,
        use2FA,
        passed2FA: false
    }

    const session = { ...token }
    // Add more sensitive information if this is the end of the auth flow
    if (!use2FA) {
        session.meta = meta
        session.email = email
        session.name = name
        session.creation = creation
    }

    return { token, session, authenticated: await bcrypt.compare(password, hash) }
}

/**
 * Authenticate 2FA for a specific user using a TOTP 6-digit token
 * key === null and use === false  means 2FA disabled
 * key !== null and use === false  means 2FA prepared
 * key !== null and use === true   means 2FA enabled
 */
async function authenticate2FA(id, totp) {
    // Explicitly ask for 2FA key because selection is disabled in the model
    let user = await User.findById(id).select('+email +key2FA')
    // If the user cannot be found
    if (!user) throw errors.not_found()

    // If the user does not use 2FA, do not reveal it is disabled
    if (!user.key2FA) throw errors.unauthorized()

    const authenticated = authenticator.verifyToken(user.key2FA, totp) !== null
    // 2FA preparation success if use was disabled but the authentication succeeded
    if (!user.use2FA && authenticated) {
        // Enable 2FA
        user = await updateById(id, { use2FA: true })
    }

    // Specify inclusion criteria to exclude new fields by default!
    const { _id, meta, email, name, use2FA, creation, verified, hash } = user.toObject()

    // Only return non-sensitive information in the taken payload
    const token = {
        _id,
        verified,
        use2FA,
        passed2FA: false
    }

    const session = {
        ...token,
        meta,
        email,
        name,
        creation
    }

    return { token, session, authenticated }
}

/**
 * Get all users from the database
 * Does not return the users' logs and hashed passwords
 */
async function getAll() {
    return User.find()
}

/**
 * Get a specific user from the databases using its MongoDB ObjectId
 * Does not return the user's log and hashed password
 */
async function getById(id, sensitive=false) {
    const query = User.findById(id)
    if (sensitive) query.select('+email')
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
async function removeById(id) {
    return User.findByIdAndRemove(id)
}

/**
 * Get a specific user from the databases using its email
 * Does not return the user's log and hashed password
 */
async function findByEmail(email) {
    return User.findOne({ email })
}

/**
 * Log an account related event
 */
async function logEvent(user, ip, type) {
    return new AccountLog({ user, ip, type }).save()
}
