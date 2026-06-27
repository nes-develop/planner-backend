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

//CORS для продакшена — разрешаем только наш домен
const allowedOrigins = process.env.NODE_ENV === 'production'
    ? ['http://45.141.103.97', 'https://45.141.103.97']
    : ['http://localhost:5173'];

app.use(cors({
    origin: allowedOrigins,
    credentials: true
}));

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

// ========== ЗАДАЧИ ==========

// Получить задачи (по дате или по неделе+год)
app.get('/api/tasks', verifyToken, async (req: AuthRequest, res: Response) => {
    try {
        const { date, weekNumber, year } = req.query
        const where: any = { userId: req.userId }

        if (date) {
            // Задачи на конкретный день
            const startDate = new Date(date as string)
            const endDate = new Date(startDate)
            endDate.setDate(endDate.getDate() + 1)
            where.date = { gte: startDate, lt: endDate }
        } else if (weekNumber && year) {
            // Задачи на неделю (type = 'weekly' или 'once' с датой в этой неделе)
            where.OR = [
                { type: 'weekly', weekNumber: parseInt(weekNumber as string), year: parseInt(year as string) },
                {
                    type: 'once',
                    date: {
                        gte: new Date(parseInt(year as string), 0, 1 + (parseInt(weekNumber as string) - 1) * 7),
                        lt: new Date(parseInt(year as string), 0, 1 + parseInt(weekNumber as string) * 7)
                    }
                }
            ]
        } else {
            return res.status(400).json({ error: 'Укажите date или weekNumber+year' })
        }

        const tasks = await prisma.task.findMany({
            where,
            orderBy: { order: 'asc' }
        })
        res.json(tasks)
    } catch (error) {
        console.error('Error fetching tasks:', error)
        res.status(500).json({ error: 'Ошибка получения задач' })
    }
})

// Создать задачу
app.post('/api/tasks', verifyToken, async (req: AuthRequest, res: Response) => {
    try {
        const { title, date, type, weekNumber, year, order } = req.body
        if (!title) {
            return res.status(400).json({ error: 'title обязателен' })
        }

        const task = await prisma.task.create({
            data: {
                title,
                userId: req.userId!,
                date: date ? new Date(date) : null,
                type: type || 'once',
                weekNumber: weekNumber || null,
                year: year || null,
                order: order || 0
            }
        })
        res.status(201).json({
            ...task,
            date: task.date ? task.date.toISOString().split('T')[0] : null
        })
    } catch (error) {
        console.error('Error creating task:', error)
        res.status(500).json({ error: 'Ошибка создания задачи' })
    }
})

// Обновить задачу
app.patch('/api/tasks/:id', verifyToken, async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params
        // Проверяем, что id — строка, а не массив
        if (!id || Array.isArray(id)) {
            return res.status(400).json({ error: 'Неверный id' })
        }

        const { title, isDone, order } = req.body

        const task = await prisma.task.update({
            where: { id },
            data: { title, isDone, order }
        })
        res.json(task)
    } catch (error) {
        console.error('Error updating task:', error)
        res.status(500).json({ error: 'Ошибка обновления задачи' })
    }
})
// Удалить задачу
app.delete('/api/tasks/:id', verifyToken, async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params
        if (!id || Array.isArray(id)) {
            return res.status(400).json({ error: 'Неверный id' })
        }

        await prisma.task.delete({ where: { id } })
        res.status(204).send()
    } catch (error) {
        console.error('Error deleting task:', error)
        res.status(500).json({ error: 'Ошибка удаления задачи' })
    }
})

app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`)
})