'use strict';

const EthCrypto = require('eth-crypto');
const axios = require("axios");

const TOKEN_VERIFY_URL = "https://iid.googleapis.com/iid/info/";

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
        console.log(error);
    }

    return null;
};

exports.auth = (req, res) => {
    (async () => {
        req.body = JSON.parse(req.body);
        console.log("request body");
        console.log(req.body);

        var response = {
            statusCode: 400,
            status: false,
            message: 'Bad request'
        };

        if(req.method != "POST" || req.body == undefined || req.body.key == undefined) {
            console.log(JSON.stringify(response));
            res.status(500).send(response);
            return;
        }

        var event = req.body;
        console.log('Incoming request with '+JSON.stringify(event));

        if(event.key == undefined || event.key == null || event.key == '' || event.token == undefined || event.token == null || event.token == '') {
            console.log(JSON.stringify(response));
            res.status(500).send(response);
            return;
        }

        var package_name = await get_package_name(event.token);

        if(package_name == null) {
            console.log(JSON.stringify(response));
            res.status(500).send(response);
            return;
        }

        var packages = process.env.PACKAGE_NAMES.split(",");
        var package_pos = packages.indexOf(package_name);

        if(package_pos<0 || package_pos>=packages.length) {
            console.log(JSON.stringify(response));
            res.status(500).send(response);
            return;
        }

        var privateKey = process.env.PRIVATE_KEY;

        const messageHash = EthCrypto.hash.keccak256(event.key);

        const signature = EthCrypto.sign(
            privateKey,
            messageHash
        );

        var response = {};
        response["sign"] = signature;
        response["statusCode"] = 200;
        response["status"] = true;
        response["message"] = 'Success';

        console.log(JSON.stringify(response));

        res.status(200).send(response);
    })();
};