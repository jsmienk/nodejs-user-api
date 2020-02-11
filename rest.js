// Require relative to project root
require('rootpath')()

const { logger, level } = require('utils/logger')
logger.setLevel(level.DEBUG)
logger.info('Starting server...')

const app = require('express')()
const cors = require('cors')
const helmet = require('helmet')
const bodyParser = require('body-parser')

const config = require('config')
const db = require('utils/db')()
const jwt = require('utils/jwt')
const errors = require('utils/errors')
// const rateLimiting = require('utils/rate-limit')  TODO
const accountEventLogger = require('utils/account-event-logger').accountEventLogger

// Register request middleware (order matters)
app.use(logger.requestLogger)
app.use(helmet())
app.use(cors())
app.use(jwt())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())
app.use(accountEventLogger)

// Register API Routes
app.use(config.API_PREFIX + '/users', require('routes/users'))
app.use(config.API_PREFIX + '/auth', require('routes/auth'))

// Register error handling middleware
app.use(errors.handleError)

// Start server
const port = config.PORT
const server = app.listen(port, () => {
    logger.info('Server listening on port: ' + port)
})

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