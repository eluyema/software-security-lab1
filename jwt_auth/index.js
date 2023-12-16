const uuid = require('uuid');
const express = require('express');
const onFinished = require('on-finished');
const bodyParser = require('body-parser');
const path = require('path');
const port = 3000;
const fs = require('fs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const JWT_SECRET = 'software-security_213';

const timeValues = Object.freeze({
    SECOND: 1,
    MINUTE: 60,
    HOUR: 60 * 60,
    DAY: 24 * 60 * 60,
});

class JWTService {
    #jwtKey = '';
    #tokenLiveTime = timeValues.HOUR;

    constructor(jwtKey, tokenLiveTime = 20 * timeValues.MINUTE ) {
        this.#jwtKey = jwtKey;
        this.#tokenLiveTime = tokenLiveTime;
    }

    sign(data, liveTime = 0 ) {
        if(liveTime) {
            return jwt.sign(data, this.#jwtKey, { expiresIn: liveTime });
        }
        return jwt.sign(data, this.#jwtKey, { expiresIn: this.#tokenLiveTime });
    }

    verify(token) {
        try {
            const decoded = jwt.verify(token, this.#jwtKey);
            return { decoded, verified: true };
        } catch(err) {
            return { decoded: null, verified: false }
        }
    }
}

const tokenService = new JWTService(JWT_SECRET);

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname+'/index.html'));
})

const users = [
    {
        login: 'Login',
        password: 'Password',
        username: 'Username1',
    },
    {
        login: 'Login1',
        password: 'Password1',
        username: 'Username1',
    }
]


const authMiddleware = (req, res, next) => {
    const bearerHeader = req.headers['authorization'];
    if(!bearerHeader) {
        res.status(401).send();
        return;
    }

    const token = bearerHeader.replace(/^Bearer\s+/, "");
    

    const { verified, decoded } = tokenService.verify(token);

    if(!verified) {
        res.status(401).send();
        return; 
    }

    const {  login } = decoded;
    req.user = { login };
    
    next();
};


app.get('/user', authMiddleware, (req, res) => {
    const user = users.find((user) => {
        if (user.login == req.user.login) {
            return true;
        }
        return false
    });

    if(user) {
        res.json({ login: user.login, username: user.username });
    } else {
        res.status(404);
    }
});

app.post('/api/login', (req, res) => {
    const { login, password } = req.body;

    const user = users.find((user) => {
        if (user.login == login && user.password == password) {
            return true;
        }
        return false
    });

    if (user) {
        const data = { login: user.login, };
        const token = tokenService.sign(data)

        res.json({ token });
    }
    res.status(401).send();
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
