import express from 'express'
const router = express.Router()

// jwt middleware
router.get('/api/secure/:token', (req, res) => res.json({}))
router.post('/api/secure', (req, res) => res.json({}))

export default router
