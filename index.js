'use strict';
const path = require('path');
const crypto = require('crypto');
const q = require('q');
const fs = require('fs');

var storedCredentials;

/**
 * File Constructor - Takes an incoming file and extracts it for username/password combinations.
 * If the passwords are not already hashed, it will hash and resave the passwords.
 * @param credentialsFile - JSON file in the format { USERNAME : PASSWORD, USERNAME2 : PASSWORD2 }, or of the hashed
 * version: e.g. { USERNAME : sha256:SALT:HASHEDPASSWORD }
 */
module.exports.init = function(credentialsFile) {
    var fileUpdates = false;
    storedCredentials = require(credentialsFile);
    console.log(JSON.stringify(storedCredentials));

    //Cycle through all the credentials and make sure they're hashed. If not, hash them & update the file.
    for (var username in storedCredentials) {
        if (storedCredentials.hasOwnProperty(username)) {
            var pwd = storedCredentials[username];
            var pwdHashDetails = /^sha256:([0-9a-fA-F]{32}):([0-9a-fA-F]{64})$/.exec(pwd);
            if(!pwdHashDetails){
                var hexSalt = crypto.randomBytes(16).toString('hex');
                storedCredentials[username] = "sha256:" + hexSalt + ":" + hashPwd(pwd, hexSalt);
                fileUpdates = true;
            }
        }
    }
    if(fileUpdates){//If updated, write new file with passwords hashed
        fs.writeFile(credentialsFile, JSON.stringify(storedCredentials), 'utf8');
    }

    return this;
}

module.exports.basicAuth = function(context){
    return extractCredentials(context).then(validateUser, send401).catch(send401);
}


/**
 * send401 - Sends a 401 request asking for valid credentials, and returns a deferred reject response.
 * @param results - An object that has { context: CONTEXT } somewhere within it for sending the response
 */
function send401(results){
    var deferred = q.defer();
    results.context.res =  {
        status: 401,
        headers: {
            "Date": "Thu, 06 Apr 2017 12:34:04 GMT",
            "Server": "Apache",
            "WWW-Authenticate": 'Basic realm="Password Protected Area"',
            "Vary": "Accept-Encoding",
            "Content-Type": "text/html; charset=iso-8859-1"

        },
        body : `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
    <html><head>
    <title>401 Authorization Required</title>
    </head><body>
    <h1>Authorization Required</h1>
    <p>This server could not verify that you
    are authorized to access the document
    requested.  Either you supplied the wrong
    credentials (e.g., bad password), or your
    browser doesn't understand how to supply
    the credentials required.</p>
    <p>Additionally, a 401 Authorization Required
    error was encountered while trying to use an ErrorDocument to handle the request.</p>
    </body></html>`
    };
    results.context.done();
    deferred.reject(false);

    return deferred.promise;
}

/**
 * extractCredentials - Takes a context object and extracts the username and password from the "Authorization" header
 * for basic credentials.
 * @param context - An Azure functions context object.
 */
function extractCredentials(context){
    var deferred = q.defer();
    try {
        if(!context.req.headers || !context.req.headers.authorization)
            deferred.reject({success:false, reason: 'No Auth Header', context: context});
        else {
            var basic = context.req.headers.authorization;
            var matches = /^Basic\s((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)$/i.exec(basic);

            //Convert Base64 -> UINT8Array -> String
            var credentialString = String.fromCharCode.apply(null, Buffer.from(matches[1], 'base64'));
            var sentCreds = /([^:]+):([^$]+)/.exec(credentialString);
            if(sentCreds)
                deferred.resolve({success: true, username: sentCreds[1], password: sentCreds[2], context: context })
            else
                deferred.reject({success: false, reason: 'Wrong format for basic credentials.', context: context});
        }
    } catch (e){
        context.log("ERROR extractCredentials" + e.message);
        deferred.reject({success: false, reason: e.message , context: context });
    }
    return deferred.promise;
}

/**
 * validateUser - Validates if the set of credentials are valid or not.
 * @param user - User object of format { username: USERNAME, password: PASSWORD, context: AZURECONTEXT }
 * @returns {*} - Promise - Resolves if the credentials are valid, rejects for any failure of if the credentials ar invalid.
 */
function validateUser(user) {
    var deferred = q.defer();
    var pwdHash = storedCredentials[user.username];
    if (!pwdHash) {//If user doesn't exist, do dummy hash call to avoid timing username enumeration
        var hexSalt = crypto.randomBytes(16).toString('hex');
        hashPwd("dummyPWD", hexSalt);
        deferred.reject({success: false, reason: 'User Does Not Exist', context: user.context});
    } else {
        var pwdHashDetails = /^sha256:([0-9a-fA-F]{32}):([0-9a-fA-F]{64})$/.exec(pwdHash);
        if (pwdHashDetails) {
            var hexSalt = pwdHashDetails[1];
            if (pwdHash === "sha256:" + hexSalt + ":" + hashPwd(user.password, hexSalt)) {
                user.context.req.user = user.username;
                deferred.resolve({success: true, user: user.username, context: user.context });
            } else {
                deferred.reject({success: false, reason: 'Invalid password', context: user.context});
            }
        } else {
            deferred.reject({success: false, reason: 'Hash not in the correct format'});
        }
    }
    return deferred.promise;
}


function hashPwd(password, hexSalt){
    const hasher = crypto.createHash('sha256');
    var salt = hex2a(hexSalt);
    var hashPwd = hasher.update(salt + password);
    for(var x =0; x < 199; x++){
        hashPwd = hasher.update(salt + hashPwd);
    }
    return hashPwd.digest('hex');
}

//From: http://stackoverflow.com/questions/3745666/how-to-convert-from-hex-to-ascii-in-javascript
function hex2a(hexx) {
    var hex = hexx.toString();//force conversion
    var str = '';
    for (var i = 0; i < hex.length; i += 2)
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
}