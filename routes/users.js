const config = require('config')
const router = require('express').Router()
const errors = require('utils/errors')
const logger = require('utils/logger').logger
const jwt = require('jsonwebtoken')
const accountEventType = require('utils/account-event-logger').enumEventType

const Users = require('collections/users')


/**
 * USERS COLLECTION
 */
router.get(   '/',    getAllUsers)
router.get(   '/:id', getUserById)
router.post(  '/',    createUser)
router.put(   '/:id', updateUserById)
router.delete('/:id', removeUserById)


/**
 * Get all users
 * <- 200 / 401 / 404 / 500
 */
function getAllUsers(req, res, next) {
    Users.getAll()
        .then(users => users && users.length ? res.status(200).json({ users }) : next(errors.not_found()))
        .catch(next)
}

/**
 * Get a specific user by its id provided as query parameter
 * @param id
 * <- 200 / 400 / 401 / 404 / 500
 */
function getUserById(req, res, next) {
    Users.getById(req.params.id, req.params.id === req.user._id)
        .then(user => user ? res.status(200).json({ user }) : next(errors.not_found()))
        .catch(next)
}

/**
 * Create a new user
 * @param email, name, password
 * <- 201 / 400 / 409 / 500
 */
function createUser(req, res, next) {
    const email = req.body.email
    const name = req.body.name
    const password = req.body.password
    const link = req.body.link

    // Check body parameters (400)
    if (!email || !name || !password || !link) {
        return next(errors.bad_request('Email, name, password, and callback link must be provided to create a user!'))
    }
    // Check password length (400)
    if (password.length < config.MIN_PASS_LENGTH) {
        return next(errors.bad_request('Password must be at least ' + config.MIN_PASS_LENGTH + ' characters long!'))
    }

    // Try to create a user (MongoDB is responsible for length/regex validation)
    Users.create(email, name, password)
        .then(user => {
            const jwtData = { verify: { _id: user._id } }
            const jwtOptions = { expiresIn: config.JWT_PW_VERIFY_TIME }
            // Generate verification JWT
            jwt.sign(jwtData, config.JWT_SECRET, jwtOptions, (err, token) => {
                if (err) return next(err)

                const verifyLink = link + token
                logger.debug('Verify link:\n' + verifyLink)

                // Email the user a verification email
                // TODO

                logger.info('Password verification email sent to "' + user._id + '".')
                res.status(201).send({ message: 'User successfully created and verification email sent.' })
            })
        })
        .catch(next)
}

/**
 * Update an existing user by its id and providing an email, and/or name, and/or password
 * @param id, email, name, password
 * <- 204 / 400 / 401 / 403 / 404 / 409 / 500
 */
function updateUserById(req, res, next) {
    // Only take what we may expect
    const params = {
        email: req.body.email,
        name: req.body.name,
        password: req.body.password
    }

    // Check if any parameters were provided (400)
    if (!params.email && !params.name && !params.password) {
        return next(errors.bad_request('Neither an email, name, or password was provided!'))
    }
    // Check password length (400)
    if (params.password && params.password.length < config.MIN_PASS_LENGTH) {
        return next(errors.bad_request('Password must be at least ' + config.MIN_PASS_LENGTH + ' characters long!'))
    }

    // Check if the user is authorized
    if (req.user._id !== req.params.id) {
        // Log information chance event
        res.accountEvent = { userId: req.params.id, type: accountEventType.INFORMATION_CHANGE_FAIL }
        return next(errors.forbidden('User can only update their own user!'))
    }

    Users.updateById(req.params.id, params)
        .then(user => {
            if (!user) return next(errors.not_found())
            // Change log information chance event type to success
            res.accountEvent = { userId: req.params.id, type: accountEventType.INFORMATION_CHANGE_SUCCESS }
            res.status(204).send()
        })
        .catch(next)
}

/**
 * Remove a specific user by its id provided as query parameter
 * @param id
 * <- 204 / 400 / 401 / 403 / 404 / 500
 */
function removeUserById(req, res, next) {
    // Check if the user is authorized
    if (req.user._id !== req.params.id) {
        return next(errors.forbidden('User can only remove their own user!'))
    }

    Users.removeById(req.params.id)
        .then(user => user ? res.status(204).send() : next(errors.not_found()))
        .catch(next)
}


module.exports = router
