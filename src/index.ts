import express, { Request, Response } from 'express'
import dotenv from 'dotenv'
import bcrypt from 'bcryptjs'
import prisma from './prisma'
import jwt from 'jsonwebtoken'
import { verifyToken, AuthRequest } from './middleware/auth'
import cors from 'cors'

dotenv.config()

console.log('JWT_SECRET from env:', process.env.JWT_SECRET)

const app = express()
const PORT = process.env.PORT || 4000

app.use(cors({
  origin: 'http://localhost:5173',  // разрешаем только наш фронт
  credentials: true
}))

app.use(express.json())

// Тестовая ручка
app.get('/ping', (req: Request, res: Response) => {
    res.json({ message: 'pong' })
})

// РЕГИСТРАЦИЯ ПОЛЬЗОВАТЕЛЯ
app.post('/auth/register', async (req: Request, res: Response) => {
    try {
        const { email, password, name } = req.body

        // Проверка, что email и пароль присланы
        if (!email || !password) {
            return res.status(400).json({ error: 'Email и пароль обязательны' })
        }

        // Проверка, существует ли уже пользователь с таким email
        const existingUser = await prisma.user.findUnique({
            where: { email }
        })

        if (existingUser) {
            return res.status(409).json({ error: 'Пользователь с таким email уже существует' })
        }

        // Хешируем пароль
        const hashedPassword = await bcrypt.hash(password, 10)

        // Создаём пользователя в базе данных
        const user = await prisma.user.create({
            data: {
                email,
                passwordHash: hashedPassword,
                name: name || null  // если имя не передали, будет null
            }
        })

        // Возвращаем пользователя (без пароля)
        res.status(201).json({
            id: user.id,
            email: user.email,
            name: user.name,
            createdAt: user.createdAt
        })

    } catch (error) {
        console.error('Registration error:', error)
        res.status(500).json({ error: 'Внутренняя ошибка сервера' })
    }
})

// ЛОГИН ПОЛЬЗОВАТЕЛЯ
app.post('/auth/login', async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body

        if (!email || !password) {
            return res.status(400).json({ error: 'Email и пароль обязательны' })
        }

        // Ищем пользователя по email
        const user = await prisma.user.findUnique({
            where: { email }
        })

        if (!user) {
            return res.status(401).json({ error: 'Неверный email или пароль' })
        }

        // Сравниваем пароль
        const isValid = await bcrypt.compare(password, user.passwordHash)

        if (!isValid) {
            return res.status(401).json({ error: 'Неверный email или пароль' })
        }

        // Генерируем JWT
        const token = jwt.sign(
            { userId: user.id, email: user.email },
            process.env.JWT_SECRET!,
            { expiresIn: '7d' }
        )

        res.json({
            token,
            user: {
                id: user.id,
                email: user.email,
                name: user.name
            }
        })

    } catch (error) {
        console.error('Login error:', error)
        res.status(500).json({ error: 'Внутренняя ошибка сервера' })
    }
})

// ЗАЩИЩЁННЫЙ МАРШРУТ (нужен токен)
app.get('/api/me', verifyToken, async (req: AuthRequest, res: Response) => {
    try {
        const user = await prisma.user.findUnique({
            where: { id: req.userId },
            select: { id: true, email: true, name: true, createdAt: true }
        })

        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' })
        }

        res.json(user)
    } catch (error) {
        console.error('Error fetching user:', error)
        res.status(500).json({ error: 'Внутренняя ошибка сервера' })
    }
})

app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`)
})