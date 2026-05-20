import express, { Request, Response } from 'express'
import dotenv from 'dotenv'
import bcrypt from 'bcryptjs'
import prisma from './prisma'

dotenv.config()

const app = express()
const PORT = process.env.PORT || 4000

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

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`)
})