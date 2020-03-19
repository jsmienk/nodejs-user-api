// Require relative to project root
require('rootpath')()

const config = require('config')

const { logger } = require('utils/logger')
// Initialize logger
logger.setLevel(config.LOG_LEVEL)
logger.info('Starting server...')

const app = require('express')()

// TODO: require('utils/rate-limit')

// Register request middleware (order matters)
app.use(logger.requestLogger)
app.use(require('cors')({ origin: config.CORS_DOMAINS, credentials: true }))
app.use(require('helmet')())
app.use(require('cookie-parser')())
app.use(require('utils/jwt')())
app.use(require('body-parser').urlencoded({ extended: false }))
app.use(require('body-parser').json())
app.use(require('utils/account-event-logger').accountEventLogger)

// Register API Routes
app.use(config.API_PREFIX + '/users',   require('routes/users'))
app.use(config.API_PREFIX + '/auth',    require('routes/auth'))

// Register error handling middleware
app.use(require('utils/errors').handleError)

// Start server
const port = config.PORT
const server = app.listen(port, () => logger.info('Server listening on port: ' + port))

const db = require('utils/db')()

// Closing server when process is stopped
process.on('SIGINT', () => {
    // Closing MongoDB connection
    logger.info('Closing MongoDB connection...')
    db.close(false, () => logger.info('MongoDB connection closed'))

    // Closing HTTP server
    logger.info('Closing server...')
    server.close(() => {
        logger.info('Server closed')
        process.exit(0)
    })
})