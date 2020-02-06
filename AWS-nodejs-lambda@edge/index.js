'use strict';

const axios = require('axios');
const querystring = require('querystring');
const AWS = require('aws-sdk');

// Config
const webSSO = {
    loginBaseUrl: 'https://uat-nusso.it.northwestern.edu/nusso/XUI/?realm=northwestern#login&authIndexType=service&authIndexValue=ldap-registry&goto=',
    checkTokenApi: 'https://northwestern-test.apigee.net/agentless-websso/validateWebSSOToken',
};

exports.handler = async(event, context, callback) => {
    // Get request and request headers
    const request = event.Records[0].cf.request;
    const cookie_jar = parseCookies(request.headers.cookie);

    // Figure out if they are authenticated.
    if (cookie_jar.nusso == null) {
        return callback(null, redirectToLogin(request));
    }

    /*
    * If you were doing this For Reals, you'd want to
    * put your Apigee API key in the SSM parameter store and 
    * look it up.
    * 
    * For this example, we're going to hard-code a fake key instead.

    // Grab the apigee apiKey from the SSM
    AWS.config.update({ region: 'us-east-1' });
    const ssm = new AWS.SSM();
    var apigeeKey = null;
    try {
        const data = await ssm.getParameter({
            Name: '/sysdevsite/prod/apigeeApiKey',
            WithDecryption: true
        }).promise();
        apigeeKey = data.Parameter.Value;
    } catch (err) {
        const response = {
            status: '500',
            statusDescription: 'Internal Error',
            body: 'Server Error. Unable to connect to AWS SSM.' + err + err.stack,
        };
        return callback(null, response);
    }
    */
    var apigeeKey = 'your-apigee-api-key-for-agentless-websso-here';

    var ssoResponse = null;
    try {
        ssoResponse = await axios.get(webSSO.checkTokenApi, { headers: { "apikey": apigeeKey, "webssotoken": cookie_jar.nusso } });
    } catch (error) {
        return callback(null, redirectToLogin(request));
    }

    const netid = getNetId(ssoResponse.data);
    if (netid == null) {
        return callback(null, redirectToLogin(request));
    }

    return callback(null, request);
};

function parseCookies(cookie_header) {
    if (cookie_header === undefined || cookie_header[0] === undefined || cookie_header[0].value === undefined) {
        return [];
    }

    var cookie_jar = {};
    const raw_cookies = cookie_header[0].value.split(';');
    for (var i = 0; raw_cookies.length > i; i++) {
        let cookie = raw_cookies[i].split('=');
        let key = cookie[0].trim();
        let value = cookie[1].trim();

        cookie_jar[key] = value;
    }

    return cookie_jar;
} // end parseCookies

function redirectToLogin(request) {
    let redirectUrl = 'https://' + request.headers.host[0].value + request.uri;
    let url = webSSO.loginBaseUrl + encodeURIComponent(redirectUrl);

    return {
        status: '302',
        statusDescription: 'Found',
        headers: {
            location: [{
                key: 'Location',
                value: url,
            }],
        },
    };
}

function getNetId(payload) {
    if ("netid" in payload) {
        return payload["netid"];
    }
    return null;
}