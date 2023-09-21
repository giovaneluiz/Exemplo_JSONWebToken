import express from "express";
import dotenv from 'dotenv'
import jwt from 'jsonwebtoken'
import fs from 'fs'

dotenv.config()
const app = express()
app.use(express.json())

const verifyJWT = (req, res, next) => {
    const token = req.headers['x-access-token']
    if (!token) {
        return res.status(401).json({ auth: false, message: 'Token Inválido!' })
    }
    jwt.verify(token, process.env.SECRET, (err, decoded) => {
        if (err) {
            return res.status(500).json({ auth: false, message: `Falha ao consultar Token: ${err}` })
        }
        req.userId = decoded.id
        next()
    })
}

const verifyJWTSecretKey = (req, res, next) => {
    const token = req.headers['x-access-token']
    if (!token) {
        return res.status(401).json({ auth: false, message: 'Token Inválido!' })
    }
    const publicKey = fs.readFileSync('./public.key', 'utf8');
    jwt.verify(token, publicKey, { algorithm: ['RS256'] }, (err, decoded) => {
        if (err) {
            return res.status(500).json({ auth: false, message: `Falha ao consultar Token: ${err}` })
        }
        req.userId = decoded.id
        next()
    })
}

app.get('/', (req, res) => {
    res.json({ message: 'ok' })
})

app.post('/login', (req, res) => {
    if (req.body.userId === 'arquiteturaWeb' && req.body.password === '123') {
        const id = 1
        const token = jwt.sign({ id }, process.env.SECRET, {
            expiresIn: 300
        })
        return res.json({ auth: true, token: token })
    }
    res.status(500).json({ message: 'Login Inválido!' })
})

app.get('/clientes', verifyJWT, (req, res, next) => {
    console.log(`${req.userId} autenticado`)
    res.json([{ id: 1, nome: 'Giovane...' }])
})

app.get('/clientes-secret', verifyJWTSecretKey, (req, res, next) => {
    console.log(`${req.userId} autenticado`)
    res.json([{ id: 1, nome: 'Giovane...' }])
})

app.post('/login-secret', (req, res) => {
    if (req.body.userId === 'arquiteturaWeb' && req.body.password === '123') {
        const id = 1
        const privateKey = fs.readFileSync('./private.key', 'utf8')
        const token = jwt.sign({ id }, privateKey, {
            expiresIn: 300,
            algorithm: 'RS256'
        })
        return res.json({ auth: true, token: token })
    }
    res.status(500).json({ message: 'Login Inválido!' })
})


app.listen(3001, console.log('Server runing'))