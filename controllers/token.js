const createError = require('http-errors')
const tokenServices = require('../services/token')
const utils = require('../utils')
const logger = require('../utils/logger')
const axios = require('axios')

/**
 * This controller is bound to the API_ROUTE_TOKEN route defined in the
 * Express routes stack. The controller tries the 'getAccessToken' method of the
 * tokenServices service, and writes the resulting status and output to the Express
 * response object. Errors from the service are caught and terminated here
 * when the response object is written
 *
 * @param {*} req - Express request object
 * @param {*} res - Express response object
 * @param {*} next - Express next object
 */
let processRequest = async (req, res, next) => {
    let authRequired = utils.parseBoolean(process.env.TOKEN_AUTHORIZATION_REQUIRED)
    let recaptchaRequired = utils.parseBoolean(process.env.TOKEN_RECAPTCHA_REQUIRED)
    let isValidTokenRequest = false

    logger.info(`New token request to ${req.originalUrl}`)

    if (authRequired) {
        isValidTokenRequest = await validateTokenRequest(req.headers, recaptchaRequired)
    }

    if (!authRequired || isValidTokenRequest) {
        try {
            const tokenBody = await tokenServices.getAccessToken()
            res.statusCode = 200
            res.setHeader('Content-Type', 'application/json')
            res.write(tokenBody)
            res.send()
            logger.info('SENT: 200 OK: token sent')
        } catch (error) {
            logger.error(`getAccessToken failed: ${error.stack}`)
            res.status(500).send(createError(500))
            logger.info('SENT: 500 Internal Server Error')
        }
    } else {
        res.status(401).send(createError(401))
    }
}

let validateTokenRequest = async (headers, recaptchaRequired) => {
    let authPasscode = `Bearer ${process.env.TOKEN_AUTHORIZATION_CODE}`
    let isValidRequest = false

    // Passcode validation
    if (!headers.hasOwnProperty('authorization')) {
        logger.warn('Token request did not contain expected authorization header')
    } else if (headers.authorization !== authPasscode) {
        logger.warn('Token request Authorization header contained an incorrect passcode')
    } else {
        isValidRequest = true
    }

    // Optional reCaptcha validation
    if (isValidRequest && recaptchaRequired) {
        let recaptchaSecretKey = process.env.TOKEN_RECAPTCHA_SECRETKEY
        if (!headers.hasOwnProperty('x-recaptcha-token')) {
            logger.warn('Token request did not contain expected x-recaptcha-token header')
            isValidRequest = false
        } else {
            isValidRequest = await recaptchaIsValidSite(recaptchaSecretKey, headers['x-recaptcha-token'])
        }
    }

    return isValidRequest
}

let recaptchaIsValidSite = async (secretKey, token) => {
    let googleAPIURL = process.env.TOKEN_RECAPTCHA_GOOGLEAPIURL
    let recaptchaQuery = `${googleAPIURL}?secret=${secretKey}&response=${token}`

    try {
        let recaptchaResponse = await axios.post(recaptchaQuery)

        if (recaptchaResponse.data.success) {
            logger.info('Recaptcha site validation successful')
            return true
        } else {
            logger.warn(`Recaptcha site validation failed: ${recaptchaResponse.data['error-codes']}`)
            return false
        }
    } catch (error) {
        logger.error(error.stack)
        return false
    }
}

module.exports = { processRequest }
