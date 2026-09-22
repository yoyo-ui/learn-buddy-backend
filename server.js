const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const { google } = require('googleapis');
const { Readable } = require('stream');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// تخزين الملفات مؤقتاً في الذاكرة (Memory Storage) لتوافقية سيرفرات Vercel
const upload = multer({ storage: multer.memoryStorage() });

// إعداد الاتصال بقاعدة البيانات مع تفعيل الـ SSL لضمان التوافق مع Supabase
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// إعداد Google Drive API باستخدام الـ Environment Variables
const auth = new google.auth.GoogleAuth({
  credentials: {
    client_email: process.env.GOOGLE_CLIENT_EMAIL,
    private_key: process.env.GOOGLE_PRIVATE_KEY ? process.env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n') : undefined,
  },
  scopes: ['https://www.googleapis.com/auth/drive.file'],
});
const drive = google.drive({ version: 'v3', auth });

// Middleware للتحقق من الـ Token (حماية الـ Routes)
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'مطلوب تسجيل الدخول أولاً' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'انتهت صلاحية الجلسة أو الرمز غير صالح' });
    req.user = user;
    next();
  });
};

// ================= 1. AUTH ROUTES =================
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM admins WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
    }

    const admin = result.rows[0];
    const isMatch = await bcrypt.compare(password, admin.password_hash);
    if (!isMatch) {
      return res.status(400).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
    }

    const token = jwt.sign({ id: admin.id, username: admin.username }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: 'تم تسجيل الدخول بنجاح', token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'خطأ في الخادم الداخلي' });
  }
});

// ================= 2. CATEGORIES (MATERIALS) CRUD =================
app.get('/api/categories', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM categories ORDER BY sort_order ASC, created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'فشل في جلب المواد' });
  }
});

app.post('/api/categories', authenticateToken, async (req, res) => {
  const { title, description, image_url, sort_order, visible } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO categories (title, description, image_url, sort_order, visible) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [title, description, image_url, sort_order || 0, visible ?? true]
    );
    res.status(201).json({ message: 'تمت إضافة المادة بنجاح', category: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'فشل في إضافة المادة' });
  }
});

app.delete('/api/categories/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM categories WHERE id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'المادة غير موجودة' });
    res.json({ message: 'تم حذف المادة بنجاح' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'فشل في حذف المادة' });
  }
});

// ================= 3. CONTENT & GOOGLE DRIVE UPLOAD =================
app.get('/api/content/category/:categoryId', async (req, res) => {
  const { categoryId } = req.params;
  try {
    const result = await pool.query('SELECT * FROM content WHERE category_id = $1 ORDER BY sort_order ASC', [categoryId]);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'فشل في جلب المحتوى' });
  }
});

app.post('/api/content', authenticateToken, upload.single('file'), async (req, res) => {
  const { category_id, title, description, content_type, thumbnail_url, sort_order, visible } = req.body;
  let fileId = null;

  try {
    if (req.file) {
      const bufferStream = new Readable();
      bufferStream.push(req.file.buffer);
      bufferStream.push(null);

      const fileMetadata = {
        name: req.file.originalname,
        parents: [process.env.GOOGLE_DRIVE_PARENT_FOLDER_ID],
      };
      
      const media = {
        mimeType: req.file.mimetype,
        body: bufferStream,
      };

      const driveResponse = await drive.files.create({
        resource: fileMetadata,
        media: media,
        fields: 'id',
      });

      fileId = driveResponse.data.id;
    }

    const result = await pool.query(
      'INSERT INTO content (category_id, title, description, content_type, file_id, thumbnail_url, sort_order, visible) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
      [category_id, title, description, content_type, fileId, thumbnail_url, sort_order || 0, visible ?? true]
    );

    res.status(201).json({ message: 'تم رفع المحتوى بنجاح', content: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'فشل في رفع المحتوى' });
  }
});

app.delete('/api/content/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM content WHERE id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'المحتوى غير موجود' });
    res.json({ message: 'تم حذف المحتوى من قاعدة البيانات بنجاح' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'فشل في حذف المحتوى' });
  }
});

// التشغيل المحلي أو التوافق مع Vercel
const PORT = process.env.PORT || 5000;
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

module.exports = app;
