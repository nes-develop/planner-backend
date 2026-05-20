import express, { Request, Response } from 'express'

const app = express()
const PORT = process.env.PORT || 4000

// Middleware для парсинга JSON
app.use(express.json())

// Тестовая ручка (проверка, что сервер работает)
app.get('/ping', (req: Request, res: Response) => {
  res.json({ message: 'pong' })
})

// Запуск сервера
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`)
})