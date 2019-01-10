const axios = require('axios');
const crypto = require('crypto');

const TOKEN_VERIFY_URL = "https://iid.googleapis.com/iid/info/";
const ALGORITHM = 'SHA256';
const SIGNATURE_FORMAT = 'hex';

var validate = async (token, package_name) => {
    let app_package_name = package_name.replace(/[.]/g,'_');

    if(process.env[app_package_name] == undefined)
        return {ok: false, message: 'Firebase id for package name '+package_name+' as '+app_package_name+' not found'};

    var params = {
        method: 'GET',
        url: TOKEN_VERIFY_URL+token,
        headers: {"Authorization": "key="+process.env[app_package_name]}
    }
    try {
        var response = await axios.request(params);
        if(response != undefined && response.data != undefined && response.data.application != undefined) {
            return {ok: (package_name == response.data.application), api_package_name: response.data.application};
        }
    } catch(error) {
        console.log('Api error:',error.message);
    }

    return {ok: false};
};

exports.handler = async (event) => {
    console.log('Incoming request with '+JSON.stringify(event));

    var response = {
        statusCode: 400,
        status: false,
        message: 'Bad request'
    };

    if(event.key == undefined || event.key == null || event.key == ''
         || event.token == undefined || event.token == null || event.token == ''
         || event.package == undefined || event.package == null || event.package == '') {
        console.log(response);
        return response;
    }

    let validate_result = await validate(event.token, event.package);

    if(!validate_result.ok) {
        console.log('validation response',JSON.stringify(validate_result));
        console.log(response);
        return response;
    }

    var privateKey = process.env.PRIVATE_KEY;

    if(privateKey.indexOf('-----BEGIN RSA PRIVATE KEY-----') < 0)
        privateKey = '-----BEGIN RSA PRIVATE KEY-----\n'+privateKey;
    else if(privateKey.indexOf('-----BEGIN RSA PRIVATE KEY-----\n') < 0)
        privateKey = privateKey.replace('-----BEGIN RSA PRIVATE KEY-----', '-----BEGIN RSA PRIVATE KEY-----\n');

    if(privateKey.indexOf('-----END RSA PRIVATE KEY-----') < 0)
        privateKey = privateKey+'\n-----END RSA PRIVATE KEY-----';
    else if(privateKey.indexOf('\n-----END RSA PRIVATE KEY-----') < 0)
        privateKey = privateKey.replace('-----END RSA PRIVATE KEY-----', '\n-----END RSA PRIVATE KEY-----');

    var sign = crypto.createSign(ALGORITHM);
    sign.update(event.key);
    var signature = sign.sign(privateKey, SIGNATURE_FORMAT);

    response["sign"] = signature;
    response["statusCode"] = 200;
    response["status"] = true;
    response["message"] = 'Success';

    console.log(response);

    return response;
};