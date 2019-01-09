const axios = require('axios');
const crypto = require('crypto');

const TOKEN_VERIFY_URL = "https://iid.googleapis.com/iid/info/";
const ALGORITHM = 'SHA256';
const SIGNATURE_FORMAT = 'hex';

var get_package_name = async (token) => {
	var params = {
		method: 'GET',
		url: TOKEN_VERIFY_URL+token,
		headers: {"Authorization": "key="+process.env.AUTHORIZATION_SERVICE_KEY}
	}
	try {
		var response = await axios.request(params);
		if(response != undefined && response.data != undefined && response.data.application != undefined)
			return response.data.application;
	} catch(error) {
		console.log(error.message);
	}

	return null;
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

    var package_name = await get_package_name(event.token);

    if(package_name == null) {
    	console.log(response);
    	return response;
    }

    if(package_name != event.package) {
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