const logger = require('utils/logger').logger

/*
error {
    title: string,
    code: number,
    message: string
}
*/
exports.create = (code, title, message) => {
    return { code, title, message }
}

// PREDEFINED ERRORS

exports.RATE_LIMIT = this.create(429, 'Rate Limit Exceeded', 'Please wait until making another request!')

// COMMON ERROR GENERATORS

exports.bad_request = (message) => {
    return this.create(400, 'Bad Request', message ? message : 'Incomplete or bad information provided!')
}

exports.unauthorized = (message) => {
    return this.create(401, 'Unauthorized', message ? message : 'Client is not authenticated!')
}

exports.pro_only = (message) => {
    return this.create(402, 'Payment Required', message ? message : 'Client is not authorized with their current payment tier!')
}

exports.forbidden = (message) => {
    return this.create(403, 'Forbidden', message ? message : 'Client is not authorized!')
}

exports.not_found = (message) => {
    return this.create(404, 'Resource Not Found', message ? message : 'The requested resource was not found or empty!')
}

exports.conflict = (message) => {
    return this.create(409, 'Conflict', message ? message : 'Resource already exists!')
}

exports.internal = (message) => {
    return this.create(500, 'Internal Server Error', message ? message : 'Not your fault!')
}


exports.fromThrown = (thrown) => {
    logger.debug(thrown)

    // Default error (500)
    let error = {
        code: thrown.code ? thrown.code : 500,
        title: thrown.name ? thrown.name : 'Error',
        message: thrown.message ? thrown.message : 'Unknown error occured!',
    }

    // MongoDB: Invalid ObjectId (400)
    if (thrown.name === 'CastError') {
        error = this.bad_request('Invalid ID parameter was provided!')
    }
    // MongoDB: Field failed validation (400)
    if (thrown.name === 'ValidationError') {
        error = this.bad_request(thrown.message)
    }
    // JWT token error (400)
    if (thrown.name === 'JsonWebTokenError') {
        error = this.create(400, 'JWT Token error', 'Invalid token was provided!')
    }
    // JWT expires error (400)
    if (thrown.name === 'TokenExpiredError') {
        error = this.create(400, 'JWT Token error', 'Expired token provided!')
    }
    // JWT authentication error (401)
    if (thrown.name === 'UnauthorizedError') {
        error = this.create(401, 'JWT Authentication Error', 'Invalid or expired token was provided!')
    }
    // MongoDB: Duplicate entry on required field (409)
    if (thrown.name === 'MongoError' && thrown.code === 11000) {
        error = this.conflict(thrown.message)
    }

    return error
}


/**
 * Middleware function to handle error responses in the correct format:
 * 
 * {
 *   title: 'title of error'
 *   message: 'message of error'
 * }
 */
exports.handleError = (thrown, req, res, next) => {
    if (!thrown) return next()
    const error = this.fromThrown(thrown)
    return res.status(error.code).json(error)
}