const config = require('config')
const expressJWT = require('express-jwt')

const Users = require('collections/users')

module.exports = () => {
    return expressJWT({ secret: config.JWT_SECRET, getToken, isRevoked }).unless({
        path: [
            // Routes that don't require authentication
            { methods: ['POST'], url: config.API_PREFIX + '/users' },  // Register
            { methods: ['POST'], url: config.API_PREFIX + '/auth/login' },  // Login
            { methods: ['POST'], url: config.API_PREFIX + '/auth/reset' },  // Request password reset
            { methods: ['PUT'], url: new RegExp(config.API_PREFIX + '/auth/reset/[a-zA-Z._]+', 'g') },  // Reset password
            { methods: ['PUT'], url: new RegExp(config.API_PREFIX + '/auth/verify/[a-zA-Z._]+', 'g') },  // Verify email
            // { methods: ['POST'], url: config.API_PREFIX + '/auth/2fa/verify' },  // Verify 2FA
        ]
    })
}

function getToken (req) {
    if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
        // Token from header
        return req.headers.authorization.split(' ')[1]
    } else if (req.cookies.token) {
        // Token from cookie
        return req.cookies.token
    }
    // No token found in request
    return null
}

async function isRevoked(_, payload, done) {
    const user = await Users.getById(payload._id)
    // Revoke token if user no longer exists
    if (!user) return done(null, true)
    // Revoke token if user did not pass 2FA (if enabled)
    if (user.use2FA && !payload.passed2FA) return done(null, true)
    done()
}