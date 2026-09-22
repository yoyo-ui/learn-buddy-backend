const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { google } = require('googleapis');
const fs = require('fs');

const app = express();
app.use(express.json());
app.use(cors());

// التأكد من وجود مجلد التخزين المؤقت للملفات
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}
const upload = multer({ dest: 'uploads/' });

// الاتصال بقاعدة بيانات Supabase باستخدام رابط الـ DATABASE_URL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// إعداد Google Drive API (تأكد من وجود ملف credentials.json أو إعدادات الخدمة)
const auth = new google.auth.GoogleAuth({
    keyFile: 'credentials.json',
    scopes: ['https://www.googleapis.com/auth/drive.file', 'https://www.googleapis.com/auth/drive.readonly']
});
const drive = google.drive({ version: 'v3', auth });

const JWT_SECRET = process.env.JWT_SECRET || 'learn_buddy_secret_key_2026';

// Middleware للتحقق من صلاحيات المشرف (Admin Auth)
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'غير مصرح لك بالوصول، يرجى تسجيل الدخول' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'انتهت صلاحية الجلسة أو الرمز غير صالح' });
        req.user = user;
        next();
    });
}

// 1. تسجيل دخول المشرف
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM admins WHERE username = $1', [username]);
        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
        }
        const admin = result.rows[0];
        const validPassword = await bcrypt.compare(password, admin.password_hash);
        if (!validPassword) {
            return res.status(400).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
        }
        const token = jwt.sign({ id: admin.id, username: admin.username }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ success: true, token });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'خطأ في الخادم أثناء تسجيل الدخول' });
    }
});

// 2. جلب جميع المواد (Categories)
app.get('/api/categories', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM categories ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'فشل في جلب المواد' });
    }
});

// 3. إضافة مادة جديدة (للمشرف فقط)
app.post('/api/categories', verifyToken, async (req, res) => {
    const { title, description } = req.body;
    try {
        const result = await pool.query(
            'INSERT INTO categories (title, description) VALUES ($1, $2) RETURNING *',
            [title, description]
        );
        res.json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'فشل في إضافة المادة' });
    }
});

// 4. حذف مادة (للمشرف فقط)
app.delete('/api/categories/:id', verifyToken, async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('DELETE FROM categories WHERE id = $1', [id]);
        res.json({ success: true, message: 'تم حذف المادة بنجاح' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'فشل في حذف المادة' });
    }
});

// 5. جلب محتوى/دروس مادة معينة
app.get('/api/content/category/:categoryId', async (req, res) => {
    const { categoryId } = req.params;
    try {
        const result = await pool.query('SELECT * FROM content WHERE category_id = $1 ORDER BY created_at ASC', [categoryId]);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'فشل في جلب المحتوى' });
    }
});

// 6. إضافة محتوى أو درس ورفعه لـ Google Drive (للمشرف فقط)
app.post('/api/content', verifyToken, upload.single('file'), async (req, res) => {
    const { category_id, title, description, content_type, file_id } = req.body;
    try {
        let finalFileId = file_id;

        // لو تم رفع ملف من الجهاز، نقوم برفعه أوتوماتيكياً لجوجل درايف
        if (req.file) {
            const fileMetadata = { name: req.file.originalname };
            const media = { mimeType: req.file.mimetype, body: fs.createReadStream(req.file.path) };
            const driveResponse = await drive.files.create({
                resource: fileMetadata,
                media: media,
                fields: 'id'
            });
            finalFileId = driveResponse.data.id;
            fs.unlinkSync(req.file.path); // حذف الملف من السيرفر المؤقت
        }

        const result = await pool.query(
            'INSERT INTO content (category_id, title, description, content_type, file_id) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [category_id, title, description, content_type, finalFileId]
        );
        res.json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'فشل في رفع وحفظ المحتوى' });
    }
});

// 7. قراءة هيكل فولدر جوجل درايف وترتيبه كأقسام ودروس تلقائياً
app.get('/api/drive-folder/:folderId', async (req, res) => {
    try {
        const parentFolderId = req.params.folderId;
        const response = await drive.files.list({
            q: `'${parentFolderId}' in parents and trashed = false`,
            fields: 'files(id, name, mimeType)',
            orderBy: 'name'
        });

        const items = response.data.files;
        let structure = [];

        for (let item of items) {
            if (item.mimeType === 'application/vnd.google-apps.folder') {
                const subResponse = await drive.files.list({
                    q: `'${item.id}' in parents and trashed = false`,
                    fields: 'files(id, name, mimeType, webViewLink)',
                    orderBy: 'name'
                });

                structure.push({
                    sectionId: item.id,
                    sectionName: item.name,
                    lessons: subResponse.data.files.map(sub => ({
                        id: sub.id,
                        title: sub.name,
                        link: sub.webViewLink,
                        type: sub.mimeType.includes('folder') ? 'subfolder' : 'file'
                    }))
                });
            }
        }
        res.json({ success: true, structure });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'فشل في قراءة فولدر جوجل درايف' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
