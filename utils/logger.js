'use strict'

const enumLevel = Object.freeze({
    DEBUG: 1,  // very verbose
    INFO: 2, // verbose
    WARN: 3, // warnings only
    QUIET: 4 // no logging
})

class Logger {
    get requestLogger() {
        return (req, res, next) => {
            // Log the request and response of any API call
            const reqLog = '\n-> ' + req.method + ' ' + req.originalUrl + '\t(' + req.ip + ')'
            const reqHeaders = req.headers
            res.on('finish', () => {
                // Request
                this.info(reqLog)
                // Log headers on debug level
                for (const header in reqHeaders) {
                    this.debug('        ' + header + ': ' + reqHeaders[header])
                }
                // Trailing new line
                this.debug('')
                // Response
                this.info('    <- ' + res.statusCode + ' ' + res.statusMessage)
                // Log headers on debug level
                const headers = res.getHeaders()
                for (const header in headers) {
                    this.debug('        ' + header + ': ' + headers[header])
                }
                // Trailing new line
                this.info('')
            })
            next()
        }
    }

    setLevel(l) {
        this.level = Object.values(enumLevel).includes(l) ? l : enumLevel.INFO
    }

    log(l, message) {
        // If allowed to log
        if (this.level !== enumLevel.QUIET) {
            // Only WARN should go through std.err
            if (l === enumLevel.WARN) {
                console.warn(message)
            } else {
                console.info(message)
            }
        }
    }

    debug(message) {
        if (enumLevel.DEBUG >= this.level) this.log(enumLevel.DEBUG, message)
    }

    info(message) {
        if (enumLevel.INFO >= this.level) this.log(enumLevel.INFO, message)
    }

    warn(message) {
        if (enumLevel.WARN >= this.level) this.log(enumLevel.WARN, message)
    }
}

const logger = new Logger()

module.exports = {
    logger,
    level: enumLevel
}