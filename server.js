/** 
* The following code contains a basic authentication service offering two different HTTP POST requests. 
* The first one is /login page that handles the login of the user. It looks for the user in the array of users,
* and after that, if the user is correctly found, generates a JWT access token for that user.
* The second one is /encode page; this one, makes use of the middleware authenticateJWT for validating the user token, verifying also the kind of request. Only HTTP requests with "Authorization: Bearer {token}" as header are accepted. 
* Once these requirements are met, the post /encode, encodes the message received from the client in base64 and returns it as a response.
*/


var express = require("express");
var crypto = require("crypto");
var app = express();
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
//To randomize the secret is possible to use crypto: crypto.randomBytes(64).toString('hex');
const secret = "d02d9fa157e117b41e35e4db7cf5034a4ef71af2fe81b0addf2a506e267ebcd02ce006682bf9dcbc65088ca6f2c62b50e40f98542cfbaa7f0a275b988b88a2ca";
var expiresIn = '20s';
var HTTP_PORT = 8000;
app.use(bodyParser.json());
dotenv.config();
process.env.TOKEN_SECRET = secret;
process.env.JWT_EXPIRES_IN = expiresIn;

// Login handler
app.post("/login", (req, res) => {
    // Read username and password from request body
    const { username, password } = req.body;
    // Filter user from the users array by username and password
    const user = users.find(u => { return u.username === username && u.password === password });

    if (user) {
        // Generate an access token
        const accessToken = generateAccessToken(user.username);
        // Return the generated token
        console.log("Generated token: " + accessToken);
        res.json({
            accessToken
        });
    } else {
        // Send this message if username or password are not found in the db
        res.send('Username or password incorrect.');
    }

});

// A middleware used to verify the token of the user and the presence of the security header
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const bearer = authHeader.split(' ')[0];
    const token = authHeader.split(' ')[1];
    console.log(bearer);
    console.log("authHeader token: " + token);
    if (bearer === "Bearer" && token) {
        // Use jwt.verify to verify the token using the TOKEN_SECRET
        jwt.verify(token, process.env.TOKEN_SECRET, (err, user) => {
            if (err) {
                return res.sendStatus(403);
            }
        req.user = user;
        next();
        });
    } else {
        // If the security header is not there, send HTTP response 500
        res.sendStatus(500);
    }
};

// JWT-secure handler
app.post("/encode", authenticateJWT, (req, res) => {
    const message = req.body.message;
    var buff = Buffer.from(message);
    var encoded = buff.toString("base64");
    res.send(encoded);
});

app.listen(HTTP_PORT, () => {
    console.log("Authentication service running on port %PORT%".replace("%PORT%",HTTP_PORT))
});

// For simplicity users are saved in an array; in production is better the use of databases such as MongoDB, SQlite, etc
const users = [
    {
        username: 'nome utente',
        password: 'xyzSafePassw0rd',
    }
];

/**
* This function generates the JWT access token for the current username.
* It makes use of jwt.sign to achieve that, taking as parameters the username, the TOKEN_SECRET to sign the jwt token, and an expiresIn parameter.
* If it is omitted, the token is supposed to have no expiration.
*/
function generateAccessToken(username) {
  return jwt.sign({username}, process.env.TOKEN_SECRET, {expiresIn: process.env.JWT_EXPIRES_IN});
}


