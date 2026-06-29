const express = require('express')
const app = express()
const router = express.Router()

app.get('/api/users', (req, res) => res.json([]))
app.get('/api/users/:id', (req, res) => res.json({}))
app.post('/api/users', (req, res) => res.json({}))
app.put('/api/users/:id', (req, res) => res.json({}))
app.delete('/api/users/:id', (req, res) => res.status(204).end())

router.get('/api/products', (req, res) => res.json([]))
router.post('/api/products', (req, res) => res.json({}))

app.listen(3000)
