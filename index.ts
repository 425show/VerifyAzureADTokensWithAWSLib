import { JwtRsaVerifier } from "aws-jwt-verify";
import express from 'express';
import bodyParser from 'body-parser';

const SERVER_PORT = process.env.PORT || 8000;
const readOnlyScope: Array<string> = ["access_as_reader"];
const readWriteScope: Array<string> = ["access_as_writer"];
let accessToken;

const config = {
    auth: {
        clientId: "c7639087-cb59-4011-88ed-5d535bafc525",
        authority: "https://login.microsoftonline.com/e801a3ad-3690-4aa0-a142-1d77cb360b07",
        jwtKeyDiscoveryEndpoint: "https://login.microsoftonline.com/common/discovery/keys"
    }
};

const verifier = JwtRsaVerifier.create({
    tokenUse: "access",
    issuer: `${config.auth.authority}/v2.0`,
    audience: config.auth.clientId,
    jwksUri: config.auth.jwtKeyDiscoveryEndpoint
  });

const validateJwt = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(' ')[1];

        try {
            const payload = await verifier.verify(token);
            console.info("Token is valid.");
            accessToken = payload;
            next();
        } catch {
            console.error("Token not valid!");
            return res.sendStatus(401);
        }
    } else {
        res.sendStatus(401);
    }
};

function confirmRequestHasTheRightScope(scopes:Array<string>): boolean{
    const tokenScopes:Array<string> = accessToken.scp.split(" ");
    scopes.forEach(scope => {
        if(!tokenScopes.includes(scope)){
            return false;
        }
    });
    return true;
}

// Create Express App and Routes
const app = express();
app.use(bodyParser.json());

app.get('/', (req, res)=>{
    var data = {
        "endpoint1": "/read",
        "endpoint2": "/write"
    };
    res.send(data); 
})

app.get('/read', validateJwt, (req, res) => {
    if(!confirmRequestHasTheRightScope(readOnlyScope)){
        res.status(403).send("Missing or invalid scope");
    };
    var data ={
        "message": "Congratulations - you read some data securely"
    }
    res.status(200).send(data);
});

app.get('/write', validateJwt, (req, res) => {
    if(!confirmRequestHasTheRightScope(readWriteScope)){
        res.status(403).send("Missing or invalid scope");
    };
    res.contentType('application/json');
    var payload = JSON.stringify(req.body);
    res.status(200).send(payload);
});

app.listen(SERVER_PORT, () => console.log(`Secure Node API is listening on port ${SERVER_PORT}!`))