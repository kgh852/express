const express = require('express')
const app = express()
const PORT = 3000
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const { PrismaClient } = require('@prisma/client')
const prisma = new PrismaClient()

app.use(express.json())

app.post('/user/register', async (req, res) => {
    const { username, password } = req.body
    try {
        const existingUser = await prisma.user.findUnique({
            where: { username }
        })
        if (existingUser) {
            return res.status(409).json({ error: '똑같은 이름의 유저가 존재합니다' })
        }

        const hashedPassword = await bcrypt.hash(password, 10)
        const createUser = await prisma.user.create({
            data: {
                username,
                password: hashedPassword
            }
        });
        res.status(201).json(createUser)
    } catch (error) {
        res.status(500).json({ error: '내부 서버 오류' })
    }
});

app.post('/user/login', async (req, res) => {
    try {
        const { username, password: inputPassword } = req.body
        const findUser = await prisma.user.findUnique({ where: { username } })

        if(!findUser) {
            const err = new Error('잘못된 정보입니다')
            err.statusCode = 400
            throw err
        }

        const { id, password: hashedPassword } = findUser
        const Validpassword = await bcrypt.compare(inputPassword, hashedPassword)

        if(!Validpassword) {
            const err = new Error('잘못된 정보입니다')
            err.statusCode = 400
            throw err
        }

        const token = jwt.sign({ id }, 'secret_key', { expiresIn: '1h'})
        res.status(200).json({ message: 'login success', token })
        }
        catch (err) {
            res.status(err.statusCode).json({ message: err.message})
        }
})

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`)
});
