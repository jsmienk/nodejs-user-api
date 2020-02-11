const RateLimiter = require('async-ratelimiter')
const Redis = require('ioredis')

const rateLimiter = new RateLimiter({ db: new Redis() })

module.exports = async (req, res, next) => {
    // Limit requests based on the IP address
    const limit = await rateLimiter.get({ id: req.ip })

    if (!res.finished && !res.headersSent) {
        res.setHeader('X-Rate-Limit-Limit', limit.total)
        res.setHeader('X-Rate-Limit-Remaining', Math.max(0, limit.remaining - 1))
        res.setHeader('X-Rate-Limit-Reset', limit.reset)
    }

    return !limit.remaining ? sendFail({
        req,
        res,
        code: HTTPStatus.TOO_MANY_REQUESTS,
        message: MESSAGES.RATE_LIMIT_EXCEEDED()
    }) : next()
}