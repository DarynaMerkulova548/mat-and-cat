const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'matemagic_secret_key_2024';

// Middleware
app.use(cors());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 хвилин
    max: 100 // максимум 100 запитів на IP за 15 хвилин
});
app.use('/api/', limiter);

// Ініціалізація бази даних
const db = new sqlite3.Database('./matemagic.db');

// Створення таблиць
db.serialize(() => {
    // Таблиця користувачів
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME,
        total_problems INTEGER DEFAULT 0,
        correct_answers INTEGER DEFAULT 0
    )`);

    // Таблиця статистики користувачів
    db.run(`CREATE TABLE IF NOT EXISTS user_stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        stats_data TEXT NOT NULL,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Таблиця сесій
    db.run(`CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        session_data TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Таблиця дій користувачів
    db.run(`CREATE TABLE IF NOT EXISTS user_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        action_data TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Таблиця відвідувань
    db.run(`CREATE TABLE IF NOT EXISTS visits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        ip_address TEXT,
        user_agent TEXT,
        visited_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);
});

// Middleware для авторизації
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Токен доступу не надано' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Недійсний токен' });
        }
        req.user = user;
        next();
    });
};

// Реєстрація
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Валідація
        if (!username || !email || !password) {
            return res.status(400).json({ message: 'Всі поля обов\'язкові' });
        }

        if (password.length < 6) {
            return res.status(400).json({ message: 'Пароль повинен містити щонайменше 6 символів' });
        }

        // Перевірка на існування користувача
        db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, email], async (err, user) => {
            if (err) {
                return res.status(500).json({ message: 'Помилка бази даних' });
            }

            if (user) {
                return res.status(400).json({ message: 'Користувач з таким ім\'ям або email вже існує' });
            }

            // Хешування паролю
            const saltRounds = 10;
            const passwordHash = await bcrypt.hash(password, saltRounds);

            // Створення користувача
            db.run('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                [username, email, passwordHash],
                function(err) {
                    if (err) {
                        return res.status(500).json({ message: 'Помилка при створенні користувача' });
                    }

                    const userId = this.lastID;
                    const token = jwt.sign({ userId, username }, JWT_SECRET, { expiresIn: '7d' });

                    res.status(201).json({
                        message: 'Користувача створено успішно',
                        user: { id: userId, username, email },
                        token
                    });
                }
            );
        });
    } catch (error) {
        res.status(500).json({ message: 'Серверна помилка' });
    }
});

// Вхід
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: 'Ім\'я користувача та пароль обов\'язкові' });
        }

        db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
            if (err) {
                return res.status(500).json({ message: 'Помилка бази даних' });
            }

            if (!user) {
                return res.status(400).json({ message: 'Невірне ім\'я користувача або пароль' });
            }

            const validPassword = await bcrypt.compare(password, user.password_hash);
            if (!validPassword) {
                return res.status(400).json({ message: 'Невірне ім\'я користувача або пароль' });
            }

            // Оновлення часу останнього входу
            db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

            const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });

            res.json({
                message: 'Вхід виконано успішно',
                user: { id: user.id, username: user.username, email: user.email },
                token
            });
        });
    } catch (error) {
        res.status(500).json({ message: 'Серверна помилка' });
    }
});

// Синхронізація статистики
app.post('/api/stats/sync', authenticateToken, (req, res) => {
    try {
        const userId = req.user.userId;
        const stats = req.body;

        // Збереження статистики в базу даних
        db.run('INSERT OR REPLACE INTO user_stats (user_id, stats_data) VALUES (?, ?)',
            [userId, JSON.stringify(stats)],
            function(err) {
                if (err) {
                    return res.status(500).json({ message: 'Помилка при збереженні статистики' });
                }

                // Оновлення загальної статистики користувача
                if (stats.totalProblems && stats.correctAnswers) {
                    db.run('UPDATE users SET total_problems = ?, correct_answers = ? WHERE id = ?',
                        [stats.totalProblems, stats.correctAnswers, userId]);
                }

                res.json({
                    message: 'Статистику синхронізовано',
                    stats: stats
                });
            }
        );
    } catch (error) {
        res.status(500).json({ message: 'Серверна помилка' });
    }
});

// Отримання статистики користувача
app.get('/api/stats/user', authenticateToken, (req, res) => {
    const userId = req.user.userId;

    db.get('SELECT stats_data FROM user_stats WHERE user_id = ? ORDER BY updated_at DESC LIMIT 1',
        [userId],
        (err, row) => {
            if (err) {
                return res.status(500).json({ message: 'Помилка бази даних' });
            }

            if (row) {
                res.json(JSON.parse(row.stats_data));
            } else {
                res.json({
                    totalProblems: 0,
                    correctAnswers: 0,
                    tableProgress: {},
                    currentStreak: 0,
                    bestStreak: 0,
                    unlockedAchievements: [],
                    catTasksSolved: 0,
                    gameScores: {}
                });
            }
        }
    );
});

// Глобальна статистика
app.get('/api/stats/global', (req, res) => {
    db.all(`
        SELECT 
            COUNT(DISTINCT users.id) as totalUsers,
            SUM(users.total_problems) as totalProblems,
            COUNT(DISTINCT sessions.id) as totalSessions
        FROM users 
        LEFT JOIN sessions ON users.id = sessions.user_id
    `, (err, rows) => {
        if (err) {
            return res.status(500).json({ message: 'Помилка бази даних' });
        }

        const stats = rows[0] || {
            totalUsers: 0,
            totalProblems: 0,
            totalSessions: 0
        };

        res.json(stats);
    });
});

// Запис сесії
app.post('/api/analytics/session', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const sessionData = req.body;

    db.run('INSERT INTO sessions (user_id, session_data) VALUES (?, ?)',
        [userId, JSON.stringify(sessionData)],
        function(err) {
            if (err) {
                console.error('Помилка при збереженні сесії:', err);
                return res.status(500).json({ message: 'Помилка при збереженні сесії' });
            }

            res.json({ message: 'Сесію записано' });
        }
    );

    // Запис відвідування
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('User-Agent');

    db.run('INSERT INTO visits (user_id, ip_address, user_agent) VALUES (?, ?, ?)',
        [userId, ip, userAgent]);
});

// Запис дії користувача
app.post('/api/analytics/action', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const { action, data } = req.body;

    db.run('INSERT INTO user_actions (user_id, action, action_data) VALUES (?, ?, ?)',
        [userId, action, JSON.stringify(data)],
        function(err) {
            if (err) {
                console.error('Помилка при збереженні дії:', err);
                return res.status(500).json({ message: 'Помилка при збереженні дії' });
            }

            res.json({ message: 'Дію записано' });
        }
    );
});

// Статистика дій (для адміністратора)
app.get('/api/analytics/actions', authenticateToken, (req, res) => {
    const { action, limit = 100 } = req.query;

    let query = `
        SELECT ua.*, u.username 
        FROM user_actions ua 
        JOIN users u ON ua.user_id = u.id 
    `;
    let params = [];

    if (action) {
        query += ' WHERE ua.action = ?';
        params.push(action);
    }

    query += ' ORDER BY ua.timestamp DESC LIMIT ?';
    params.push(parseInt(limit));

    db.all(query, params, (err, rows) => {
        if (err) {
            return res.status(500).json({ message: 'Помилка бази даних' });
        }

        res.json(rows);
    });
});

// Запуск сервера
app.listen(PORT, () => {
    console.log(`Сервер запущено на порту ${PORT}`);
    console.log(`API доступно за адресою: http://localhost:${PORT}/api`);
});

// Обробка помилок
process.on('uncaughtException', (err) => {
    console.error('Необроблена помилка:', err);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Необроблене відхилення промісу:', reason);
});