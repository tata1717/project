require('dotenv').config();

const express = require('express');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise');
const MySQLStore = require('express-mysql-session')(session);
const multer = require('multer');

const PORT = process.env.PORT || 3000;
const app = express();
const uploadsDir = path.join(__dirname, 'public', 'uploads');
const fsPromises = fs.promises;

if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const dbConfig = {
  host: process.env.MYSQL_HOST || 'localhost',
  port: Number(process.env.MYSQL_PORT || 3306),
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWORD || '',
  database: process.env.MYSQL_DATABASE || 'ideindyo_projectnode',
  waitForConnections: true,
  connectionLimit: 10,
  namedPlaceholders: true
};


const pool = mysql.createPool(dbConfig);

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    const extension = path.extname(file.originalname || '');
    cb(null, `upload-${uniqueSuffix}${extension}`);
  }
});

const imageFileFilter = (req, file, cb) => {
  if (!file.mimetype.startsWith('image/')) {
    cb(new Error('รองรับเฉพาะไฟล์ภาพเท่านั้น'));
  } else {
    cb(null, true);
  }
};

const allowAllFileFilter = (req, file, cb) => cb(null, true);

const createUploader = ({ fileSizeMB, fileFilter = allowAllFileFilter, filesLimit }) => {
  const limits = {
    fileSize: Math.max(fileSizeMB, 1) * 1024 * 1024
  };
  if (filesLimit) {
    limits.files = filesLimit;
  }
  return multer({
    storage,
    fileFilter,
    limits
  });
};

const profileImageUploader = createUploader({ fileSizeMB: 2, fileFilter: imageFileFilter });
const sliderImageUploader = createUploader({ fileSizeMB: 5, fileFilter: imageFileFilter });
const siteBrandUploader = createUploader({ fileSizeMB: 2, fileFilter: imageFileFilter, filesLimit: 1 });

const newsFileFilter = (req, file, cb) => {
  if (file.fieldname === 'image') {
    if (!file.mimetype.startsWith('image/')) {
      cb(new Error('กรุณาอัปโหลดไฟล์ภาพสำหรับหน้าปก'));
    } else {
      cb(null, true);
    }
  } else if (file.fieldname === 'attachments') {
    cb(null, true);
  } else {
    cb(new Error('ไม่รองรับการอัปโหลดไฟล์ประเภทนี้'));
  }
};

const newsUploader = multer({
  storage,
  fileFilter: newsFileFilter,
  limits: {
    fileSize: 50 * 1024 * 1024,
    files: 11
  }
});

const removeFileIfExists = async (relativePath) => {
  if (!relativePath) {
    return;
  }
  const absolutePath = path.join(__dirname, 'public', relativePath);
  try {
    await fsPromises.unlink(absolutePath);
  } catch (error) {
    if (error.code !== 'ENOENT') {
      console.warn(`ไม่สามารถลบไฟล์เก่าได้: ${absolutePath}`, error);
    }
  }
};

const generateNewsSlug = (title = '') => {
  const base = title
    .toLowerCase()
    .trim()
    .replace(/[^\p{L}\p{N}]+/gu, '-')
    .replace(/^-+|-+$/g, '');
  const unique = Math.round(Math.random() * 1e9);
  return `${base || 'news'}-${Date.now()}-${unique}`;
};

const toPublicUploadPath = (filename) => {
  if (!filename) {
    return null;
  }
  return path.posix.join('uploads', filename);
};

const stripHtml = (html = '') =>
  html
    .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?>[\s\S]*?<\/style>/gi, '')
    .replace(/<\/?[^>]+(>|$)/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

const cleanupUploadedFiles = async (files = []) => {
  if (!files) {
    return;
  }
  const fileList = Array.isArray(files) ? files : Object.values(files).flat();
  await Promise.all(
    fileList
      .filter((file) => file && file.filename)
      .map((file) => removeFileIfExists(toPublicUploadPath(file.filename)))
  );
};

const decodeFilename = (name = '') => {
  try {
    return Buffer.from(name, 'latin1').toString('utf8');
  } catch (error) {
    return name;
  }
};

const defaultSiteSettings = {
  siteName: 'ระบบจัดการสมาชิก',
  siteStatus: 'open',
  siteLogoPath: null
};

let siteSettingsCache = {
  data: null,
  expiresAt: 0
};

const invalidateSiteSettingsCache = () => {
  siteSettingsCache = { data: null, expiresAt: 0 };
};

const mapSiteSettingsFromRows = (rows = []) => {
  const settings = { ...defaultSiteSettings };
  rows.forEach((row) => {
    const key = row.setting_key;
    const value = row.setting_value;
    switch (key) {
      case 'site_name':
        settings.siteName = value?.trim() ? value.trim() : defaultSiteSettings.siteName;
        break;
      case 'site_status':
        settings.siteStatus = value === 'closed' ? 'closed' : 'open';
        break;
      case 'site_logo':
        settings.siteLogoPath = value?.trim() ? value.trim() : null;
        break;
      default:
        break;
    }
  });
  settings.siteLogoUrl = settings.siteLogoPath ? `/${settings.siteLogoPath}` : null;
  settings.isClosed = settings.siteStatus === 'closed';
  return settings;
};

const loadSiteSettings = async ({ force = false } = {}) => {
  if (!force && siteSettingsCache.data && siteSettingsCache.expiresAt > Date.now()) {
    return siteSettingsCache.data;
  }
  const [rows] = await pool.query('SELECT setting_key, setting_value FROM site_settings');
  const settings = mapSiteSettingsFromRows(rows);
  siteSettingsCache = {
    data: settings,
    expiresAt: Date.now() + 60_000
  };
  return settings;
};

const setSiteSetting = async (key, value) => {
  await pool.query(
    `INSERT INTO site_settings (setting_key, setting_value)
     VALUES (?, ?)
     ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)`,
    [key, value]
  );
};

const updateSiteSettingsBulk = async (entries = []) => {
  if (!entries.length) {
    return;
  }
  await Promise.all(
    entries.map(({ key, value }) =>
      pool.query(
        `INSERT INTO site_settings (setting_key, setting_value)
         VALUES (?, ?)
         ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)`,
        [key, value]
      )
    )
  );
  invalidateSiteSettingsCache();
};

const composeNewsUploads = (redirectPathResolver) => (req, res, next) => {
  newsUploader.fields([
    { name: 'image', maxCount: 1 },
    { name: 'attachments', maxCount: 10 }
  ])(req, res, async (error) => {
    if (error) {
      console.error('เกิดข้อผิดพลาดในการอัปโหลดไฟล์ข่าว:', error);
      await cleanupUploadedFiles(req.files);
      let message = 'ไม่สามารถอัปโหลดไฟล์ข่าวได้';
      if (error.code === 'LIMIT_FILE_SIZE') {
        message = 'ไฟล์ที่อัปโหลดมีขนาดเกิน 50 MB';
      } else if (error.code === 'LIMIT_FILE_COUNT') {
        message = 'ไม่สามารถอัปโหลดไฟล์แนบเกิน 10 ไฟล์ต่อครั้ง';
      } else if (error.code === 'LIMIT_UNEXPECTED_FILE') {
        message = 'รูปแบบการอัปโหลดไม่ถูกต้อง กรุณาลองใหม่อีกครั้ง';
      } else if (error.message) {
        message = error.message;
      }
      setFlash(req, 'error', message);
      return res.redirect(redirectPathResolver(req));
    }

    const imageFile = req.files?.image?.[0];
    if (imageFile && imageFile.size > 8 * 1024 * 1024) {
      await cleanupUploadedFiles(req.files);
      setFlash(req, 'error', 'ภาพหน้าปกต้องมีขนาดไม่เกิน 8 MB');
      return res.redirect(redirectPathResolver(req));
    }

    const attachments = req.files?.attachments || [];
    const oversized = attachments.find((file) => file.size > 50 * 1024 * 1024);
    if (oversized) {
      await cleanupUploadedFiles(req.files);
      setFlash(req, 'error', `ไฟล์ ${oversized.originalname} มีขนาดเกิน 50 MB`);
      return res.redirect(redirectPathResolver(req));
    }

    return next();
  });
};

let sessionStore;
try {
  sessionStore = new MySQLStore({
    host: dbConfig.host,
    port: dbConfig.port,
    user: dbConfig.user,
    password: dbConfig.password,
    database: dbConfig.database,
    createDatabaseTable: true,
    charset: 'utf8mb4_unicode_ci',
    clearExpired: true, // ล้าง session ที่หมดอายุอัตโนมัติ
    checkExpirationInterval: 15 * 60 * 1000, // ตรวจสอบทุก 15 นาที
    expiration: 90 * 24 * 60 * 60 * 1000, // 90 วัน (ต้องตรงกับ maxAge ของ cookie)
    schema: {
      tableName: 'sessions',
      columnNames: {
        session_id: 'session_id',
        expires: 'expires',
        data: 'data'
      }
    }
  });
} catch (error) {
  console.error('ไม่สามารถเชื่อมต่อฐานข้อมูล MySQL สำหรับ session store ได้:', error);
  process.exit(1);
}

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: false }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'change-this-secret',
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    name: 'sessionId',
    cookie: { 
      httpOnly: true, 
      sameSite: 'lax', 
      secure: false,
      maxAge: 90 * 24 * 60 * 60 * 1000 // 90 วัน (session จะอยู่จนกว่าจะออกจากระบบ)
    },
    rolling: true // ขยายอายุ session เมื่อมีการใช้งานทุกครั้ง
  })
);

app.use(express.static(path.join(__dirname, 'public')));

// Service Worker route - ensure correct content-type
app.get('/sw.js', (req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  res.setHeader('Service-Worker-Allowed', '/');
  res.sendFile(path.join(__dirname, 'public', 'sw.js'));
});

app.use(async (req, res, next) => {
  try {
    const siteSettings = await loadSiteSettings();
    res.locals.site = siteSettings;
    
    // ตรวจสอบ session และแสดงข้อมูลผู้ใช้ - ไม่ทำลาย session
    // rolling: true จะขยายอายุ session อัตโนมัติเมื่อมีการใช้งาน
    if (req.session && req.session.user && req.session.user.role) {
      res.locals.currentUser = req.session.user;
    } else {
      res.locals.currentUser = null;
    }
    
    res.locals.error = req.session?.error || null;
    res.locals.success = req.session?.success || null;
    
    if (req.session) {
      delete req.session.error;
      delete req.session.success;
    }

    if (siteSettings.isClosed) {
      const isAdminUser = req.session?.user?.role === 'admin';
      const exemptPaths = ['/login', '/logout'];
      const isExemptPath = exemptPaths.includes(req.path);
      const isAdminRoute = req.path.startsWith('/admin');

      if (!isAdminUser && !isExemptPath && !isAdminRoute) {
        return res.status(503).render('maintenance', { title: 'ปิดปรับปรุงชั่วคราว' });
      }
    }

    return next();
  } catch (error) {
    console.error('เกิดข้อผิดพลาดใน middleware:', error);
    // ถ้าเกิด error ให้ล้าง currentUser แต่ไม่ทำลาย session
    res.locals.currentUser = null;
    return next(error);
  }
});

const allowedRoles = ['admin', 'staff'];

const setFlash = (req, type, message) => {
  req.session[type] = message;
};

const getRedirectForRole = (role) => {
  if (role === 'admin') return '/admin/dashboard';
  if (role === 'staff') return '/staff/dashboard';
  return '/';
};

const requireAuth = (req, res, next) => {
  if (!req.session.user) {
    setFlash(req, 'error', 'กรุณาเข้าสู่ระบบก่อน');
    return res.redirect('/login');
  }
  return next();
};

const requireRole = (role) => (req, res, next) => {
  if (!req.session.user || req.session.user.role !== role) {
    setFlash(req, 'error', 'คุณไม่มีสิทธิ์เข้าถึงหน้านี้');
    return res.redirect('/');
  }
  return next();
};

const renderHomePage = async (req, res) => {
  try {
    const [newsRows] = await pool.query(
      `SELECT
         n.id,
         n.title,
         n.slug,
         n.content,
         n.image_path,
         n.image_caption,
         n.created_at,
         n.category_id,
         u.name AS author_name,
         u.profile_image AS author_image,
         u.position AS author_position,
         u.affiliation AS author_affiliation,
         nc.name AS category_name,
         nc.color AS category_color,
         (SELECT COUNT(*) FROM news_files nf WHERE nf.news_id = n.id) AS attachment_count
       FROM news n
       LEFT JOIN users u ON n.author_id = u.id
       LEFT JOIN news_categories nc ON n.category_id = nc.id
       WHERE n.is_published = 1
       ORDER BY n.created_at DESC
       LIMIT 6`
    );
    const news = newsRows.map((row) => ({
      id: row.id,
      title: row.title,
      slug: row.slug,
      preview: (() => {
        const text = stripHtml(row.content);
        if (text.length <= 220) return text;
        return `${text.slice(0, 220).trimEnd()}…`;
      })(),
      imagePath: row.image_path,
      imageCaption: row.image_caption,
      category: row.category_name ? {
        id: row.category_id,
        name: row.category_name,
        color: row.category_color
      } : null,
      author: {
        name: row.author_name || 'ทีมผู้ดูแลระบบ',
        image: row.author_image,
        position: row.author_position,
        affiliation: row.author_affiliation
      },
      attachmentCount: Number.parseInt(row.attachment_count, 10) || 0,
      createdAt: row.created_at
    }));
    const [sliderRows] = await pool.query(
      `SELECT id, title, caption, link, image_path, is_active, display_order, created_at
       FROM slider_images
       WHERE is_active = 1
       ORDER BY display_order ASC, created_at DESC
       LIMIT 10`
    );
    let sliderImages = sliderRows.map((row) => ({
      id: row.id,
      title: row.title,
      description: row.caption || '',
      imagePath: row.image_path,
      link: row.link && row.link.trim() ? row.link.trim() : null,
      author: null,
      createdAt: row.created_at
    }));

    if (!sliderImages.length) {
      sliderImages = news
        .filter((item) => item.imagePath)
        .slice(0, 5)
        .map((item) => ({
          id: item.id,
          title: item.title,
          description: item.preview,
          imagePath: item.imagePath,
          link: `/news/${item.slug}`,
          author: item.author,
          createdAt: item.createdAt
        }));
    }

    // ดึงข้อมูลหมวดเมนูและเมนูย่อ
    const [menuCategoryRows] = await pool.query(
      `SELECT 
         mc.id, 
         mc.name, 
         mc.description, 
         mc.icon, 
         mc.color, 
         mc.display_order
       FROM menu_categories mc
       WHERE mc.is_active = 1
       ORDER BY mc.display_order ASC, mc.created_at ASC`
    );

    const [menuItemRows] = await pool.query(
      `SELECT 
         mi.id, 
         mi.title, 
         mi.description, 
         mi.link, 
         mi.image_path, 
         mi.display_order,
         mc.id as category_id,
         mc.name as category_name,
         mc.color as category_color
       FROM menu_items mi
       LEFT JOIN menu_categories mc ON mi.category_id = mc.id
       WHERE mi.is_active = 1 AND mc.is_active = 1
       ORDER BY mc.display_order ASC, mi.display_order ASC, mi.created_at ASC`
    );

    const menuCategories = menuCategoryRows.map((row) => ({
      id: row.id,
      name: row.name,
      description: row.description,
      icon: row.icon,
      color: row.color,
      displayOrder: row.display_order
    }));

    const menuItems = menuItemRows.map((row) => ({
      id: row.id,
      title: row.title,
      description: row.description,
      link: row.link,
      imagePath: row.image_path,
      displayOrder: row.display_order,
      categoryId: row.category_id,
      categoryName: row.category_name,
      categoryColor: row.category_color
    }));

    // จัดกลุ่มเมนูย่อตามหมวด
    const menuItemsByCategory = {};
    menuItems.forEach((item) => {
      if (!menuItemsByCategory[item.categoryId]) {
        menuItemsByCategory[item.categoryId] = [];
      }
      menuItemsByCategory[item.categoryId].push(item);
    });

    // เพิ่มเมนูย่อให้กับหมวดเมนู
    const menuCategoriesWithItems = menuCategories.map((category) => ({
      ...category,
      items: menuItemsByCategory[category.id] || []
    }));

    // ดึงข้อมูลหมวดหมู่ข่าว
    const [newsCategoryRows] = await pool.query(
      `SELECT 
         nc.id, 
         nc.name, 
         nc.color,
         COUNT(n.id) as news_count
       FROM news_categories nc
       LEFT JOIN news n ON nc.id = n.category_id AND n.is_published = 1
       WHERE nc.is_active = 1
       GROUP BY nc.id, nc.name, nc.color
       ORDER BY nc.display_order ASC, nc.name ASC`
    );
    
    const newsCategories = newsCategoryRows.map((row) => ({
      id: row.id,
      name: row.name,
      color: row.color,
      newsCount: Number.parseInt(row.news_count, 10) || 0
    }));

    return res.render('home', {
      title: 'หน้าแรก',
      news,
      sliderImages,
      menuCategories: menuCategoriesWithItems,
      newsCategories
    });
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการดึงข่าวประชาสัมพันธ์:', error);
    return res.render('home', { 
      title: 'หน้าแรก', 
      news: [], 
      sliderImages: [], 
      menuCategories: [] 
    });
  }
};

app.get('/', async (req, res) => {
  try {
    // ตรวจสอบ session อย่างระมัดระวัง และมี user data ที่ครบถ้วน
    const hasUser = req.session && req.session.user && req.session.user.role;
    
    // ถ้ามีผู้ใช้และไม่ได้ต้องการดูหน้า public ให้ redirect ไป dashboard
    if (hasUser && req.query.view !== 'public') {
      try {
        const redirectPath = getRedirectForRole(req.session.user.role);
        // ตรวจสอบว่า redirect path ไม่ใช่ current path เพื่อหลีกเลี่ยง infinite redirect
        if (redirectPath && redirectPath !== req.path) {
          return res.redirect(redirectPath);
        }
      } catch (redirectError) {
        console.error('เกิดข้อผิดพลาดในการ redirect:', redirectError);
        // ถ้า redirect มีปัญหา ให้แสดงหน้า home แทน
      }
    }
    
    // แสดงหน้า home
    return renderHomePage(req, res);
  } catch (error) {
    console.error('เกิดข้อผิดพลาดใน route /:', error);
    // ถ้าเกิด error ให้แสดงหน้า home โดยไม่ redirect
    return renderHomePage(req, res);
  }
});

app.get('/home', async (req, res) => {
  try {
    return renderHomePage(req, res);
  } catch (error) {
    console.error('เกิดข้อผิดพลาดใน route /home:', error);
    return renderHomePage(req, res);
  }
});

app.get('/register', (req, res) => {
  const isAdmin = req.session.user?.role === 'admin';
  return res.render('register', {
    title: 'สมัครสมาชิก',
    isAdmin
  });
});

app.post('/register', async (req, res) => {
  const { name, email, password, phone, position, affiliation, role } = req.body;

  if (!name || !email || !password || !phone || !position || !affiliation) {
    setFlash(req, 'error', 'กรุณากรอกข้อมูลให้ครบถ้วน รวมถึงเบอร์โทรศัพท์ ตำแหน่ง และสังกัด');
    return res.redirect('/register');
  }

  const normalizedEmail = email.trim().toLowerCase();
  const trimmedName = name.trim();
  const trimmedPhone = phone.trim();
  const trimmedPosition = position.trim();
  const trimmedAffiliation = affiliation.trim();

  try {
    const [existing] = await pool.query('SELECT id FROM users WHERE email = ?', [normalizedEmail]);
    if (existing.length) {
      setFlash(req, 'error', 'อีเมลนี้ถูกใช้งานแล้ว');
      return res.redirect('/register');
    }

    const passwordHash = await bcrypt.hash(password, 10);

    let roleToSave = 'staff';
    let isApproved = 0;
    if (req.session.user?.role === 'admin' && allowedRoles.includes(role)) {
      roleToSave = role;
      isApproved = 1;
    }

    await pool.query(
      'INSERT INTO users (name, email, phone, `position`, affiliation, profile_image, password_hash, role, is_approved) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [
        trimmedName,
        normalizedEmail,
        trimmedPhone,
        trimmedPosition,
        trimmedAffiliation,
        null,
        passwordHash,
        roleToSave,
        isApproved
      ]
    );

    if (isApproved) {
      setFlash(req, 'success', 'สร้างบัญชีผู้ใช้ใหม่สำเร็จแล้ว');
    } else {
      setFlash(req, 'success', 'สมัครสมาชิกสำเร็จแล้ว กรุณารอผู้ดูแลระบบยืนยันบัญชี');
    }
    return res.redirect('/login');
  } catch (error) {
    console.error('เกิดข้อผิดพลาดระหว่างการสมัครสมาชิก:', error);
    setFlash(req, 'error', 'ไม่สามารถสมัครสมาชิกได้ กรุณาลองใหม่อีกครั้ง');
    return res.redirect('/register');
  }
});

app.get('/login', (req, res) => {
  // ถ้ามี session user อยู่ ให้ redirect ไป dashboard
  if (req.session && req.session.user) {
    return res.redirect(getRedirectForRole(req.session.user.role));
  }
  
  // เพิ่ม headers เพื่อป้องกัน cache เมื่อ logout
  if (req.query.logout === 'success') {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
  
  return res.render('login', { title: 'เข้าสู่ระบบ' });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    setFlash(req, 'error', 'กรุณากรอกอีเมลและรหัสผ่าน');
    return res.redirect('/login');
  }

  try {
    const normalizedEmail = email.trim().toLowerCase();
    const [users] = await pool.query(
      'SELECT id, name, email, phone, `position`, affiliation, profile_image, role, password_hash, is_approved FROM users WHERE email = ?',
      [normalizedEmail]
    );

    if (!users.length) {
      setFlash(req, 'error', 'ไม่พบผู้ใช้งาน');
      return res.redirect('/login');
    }

    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      setFlash(req, 'error', 'รหัสผ่านไม่ถูกต้อง');
      return res.redirect('/login');
    }

    if (!user.is_approved) {
      setFlash(
        req,
        'error',
        'บัญชีของคุณยังไม่ได้รับการยืนยันจากผู้ดูแลระบบ กรุณารอการอนุมัติ'
      );
      return res.redirect('/login');
    }

    req.session.user = {
      id: user.id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      position: user.position,
      affiliation: user.affiliation,
      profileImage: user.profile_image,
      role: user.role,
      isApproved: Boolean(user.is_approved)
    };

    setFlash(req, 'success', `ยินดีต้อนรับคุณ ${user.name}`);
    return res.redirect(getRedirectForRole(user.role));
  } catch (error) {
    console.error('เกิดข้อผิดพลาดระหว่างการเข้าสู่ระบบ:', error);
    setFlash(req, 'error', 'ไม่สามารถเข้าสู่ระบบได้ กรุณาลองใหม่');
    return res.redirect('/login');
  }
});

app.post('/logout', requireAuth, (req, res) => {
  // เก็บชื่อ session cookie ก่อน destroy
  const sessionId = req.sessionID;
  
  // ล้างข้อมูล user จาก session
  req.session.user = null;
  delete req.session.user;
  
  // Destroy session
  req.session.destroy((error) => {
    // ล้าง session cookie ออกหมด
    if (req.cookies && req.cookies.sessionId) {
      res.clearCookie('sessionId', {
        httpOnly: true,
        sameSite: 'lax',
        secure: false,
        path: '/'
      });
    }
    
    // ล้าง cookie อื่นๆ ที่อาจเกี่ยวข้อง
    res.clearCookie('connect.sid', { path: '/' });
    
    if (error) {
      console.error('เกิดข้อผิดพลาดระหว่างออกจากระบบ:', error);
      setFlash(req, 'error', 'ไม่สามารถออกจากระบบได้ กรุณาลองใหม่');
      return res.redirect('/');
    }
    
    // เพิ่ม headers เพื่อป้องกัน cache
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    
    // Redirect ไปหน้า login พร้อม query parameter เพื่อบังคับ reload
    return res.redirect('/login?logout=success&_t=' + Date.now());
  });
});

app.get('/profile', requireAuth, async (req, res) => {
  const userId = req.session.user.id;
  try {
    const [users] = await pool.query(
      'SELECT id, name, email, phone, `position`, affiliation, profile_image FROM users WHERE id = ?',
      [userId]
    );
    if (!users.length) {
      setFlash(req, 'error', 'ไม่พบข้อมูลผู้ใช้');
      return res.redirect('/');
    }

    const user = users[0];
    return res.render('profile', {
      title: 'โปรไฟล์ของฉัน',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        position: user.position,
        affiliation: user.affiliation,
        profileImage: user.profile_image
      }
    });
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการโหลดโปรไฟล์:', error);
    setFlash(req, 'error', 'ไม่สามารถโหลดโปรไฟล์ได้');
    return res.redirect('/');
  }
});

app.post(
  '/profile',
  requireAuth,
  (req, res, next) => {
    profileImageUploader.single('profileImage')(req, res, (err) => {
      if (err) {
        console.error('เกิดข้อผิดพลาดในการอัปโหลดรูปโปรไฟล์:', err);
        setFlash(req, 'error', err.message || 'ไม่สามารถอัปโหลดรูปโปรไฟล์ได้');
        return res.redirect('/profile');
      }
      return next();
    });
  },
  async (req, res) => {
    const userId = req.session.user.id;
    const { name, phone, position, affiliation } = req.body;

    if (!name || !phone || !position || !affiliation) {
      setFlash(req, 'error', 'กรุณากรอกข้อมูลให้ครบถ้วน');
      return res.redirect('/profile');
    }

    const trimmedName = name.trim();
    const trimmedPhone = phone.trim();
    const trimmedPosition = position.trim();
    const trimmedAffiliation = affiliation.trim();

    try {
      const [users] = await pool.query(
        'SELECT profile_image FROM users WHERE id = ?',
        [userId]
      );
      if (!users.length) {
        setFlash(req, 'error', 'ไม่พบข้อมูลผู้ใช้');
        return res.redirect('/profile');
      }

      let profileImagePath = users[0].profile_image;
      if (req.file) {
        const newPath = toPublicUploadPath(req.file.filename);
        await removeFileIfExists(profileImagePath);
        profileImagePath = newPath;
      }

      await pool.query(
        'UPDATE users SET name = ?, phone = ?, `position` = ?, affiliation = ?, profile_image = ? WHERE id = ?',
        [
          trimmedName,
          trimmedPhone,
          trimmedPosition,
          trimmedAffiliation,
          profileImagePath,
          userId
        ]
      );

      req.session.user = {
        ...req.session.user,
        name: trimmedName,
        phone: trimmedPhone,
        position: trimmedPosition,
        affiliation: trimmedAffiliation,
        profileImage: profileImagePath
      };

      setFlash(req, 'success', 'อัปเดตโปรไฟล์เรียบร้อยแล้ว');
      return res.redirect('/profile');
    } catch (error) {
      console.error('เกิดข้อผิดพลาดในการอัปเดตโปรไฟล์:', error);
      setFlash(req, 'error', 'ไม่สามารถอัปเดตโปรไฟล์ได้');
      return res.redirect('/profile');
    }
  }
);

app.get('/admin/dashboard', requireRole('admin'), async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id, name, email, phone, `position`, affiliation, role, is_approved, created_at FROM users ORDER BY created_at DESC'
    );
    const users = rows.map((row) => ({
      id: row.id,
      name: row.name,
      email: row.email,
      phone: row.phone,
      position: row.position,
      affiliation: row.affiliation,
      role: row.role,
      isApproved: Boolean(row.is_approved),
      createdAt: row.created_at
    }));

    return res.render('admin-dashboard', {
      title: 'แดชบอร์ดผู้ดูแลระบบ',
      users
    });
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการดึงข้อมูลผู้ใช้:', error);
    setFlash(req, 'error', 'ไม่สามารถโหลดข้อมูลผู้ใช้ได้');
    return res.redirect('/');
  }
});

app.get('/admin/users', requireRole('admin'), async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id, name, email, phone, `position`, affiliation, role, is_approved, created_at FROM users ORDER BY created_at DESC'
    );
    const users = rows.map((row) => ({
      id: row.id,
      name: row.name,
      email: row.email,
      phone: row.phone,
      position: row.position,
      affiliation: row.affiliation,
      role: row.role,
      isApproved: Boolean(row.is_approved),
      createdAt: row.created_at
    }));

    return res.render('admin-users', {
      title: 'จัดการสมาชิก',
      users
    });
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการดึงข้อมูลผู้ใช้:', error);
    setFlash(req, 'error', 'ไม่สามารถโหลดข้อมูลผู้ใช้ได้');
    return res.redirect('/admin/dashboard');
  }
});

app.post('/admin/users/:id/approval', requireRole('admin'), async (req, res) => {
  const userId = Number.parseInt(req.params.id, 10);
  const { action } = req.body;

  if (!Number.isInteger(userId)) {
    setFlash(req, 'error', 'ผู้ใช้ไม่ถูกต้อง');
    return res.redirect('/admin/dashboard');
  }

  if (!['approve', 'revoke'].includes(action)) {
    setFlash(req, 'error', 'การดำเนินการไม่ถูกต้อง');
    return res.redirect('/admin/dashboard');
  }

  const shouldApprove = action === 'approve';

  if (req.session.user.id === userId && !shouldApprove) {
    setFlash(req, 'error', 'ไม่สามารถยกเลิกการยืนยันบัญชีของตนเองได้');
    return res.redirect('/admin/dashboard');
  }

  try {
    const [users] = await pool.query(
      'SELECT id, name, role, is_approved FROM users WHERE id = ?',
      [userId]
    );

    if (!users.length) {
      setFlash(req, 'error', 'ไม่พบผู้ใช้');
      return res.redirect('/admin/dashboard');
    }

    const user = users[0];

    if (user.role === 'admin' && !shouldApprove) {
      setFlash(req, 'error', 'ไม่สามารถยกเลิกการยืนยันบัญชีของผู้ดูแลระบบได้');
      return res.redirect('/admin/dashboard');
    }

    if (Boolean(user.is_approved) === shouldApprove) {
      setFlash(
        req,
        'success',
        shouldApprove
          ? `บัญชีของ ${user.name} ได้รับการยืนยันแล้ว`
          : `บัญชีของ ${user.name} ถูกยกเลิกการยืนยันอยู่แล้ว`
      );
      return res.redirect('/admin/dashboard');
    }

    await pool.query('UPDATE users SET is_approved = ? WHERE id = ?', [
      shouldApprove ? 1 : 0,
      userId
    ]);

    const message = shouldApprove
      ? `ยืนยันบัญชีของ ${user.name} แล้ว`
      : `ยกเลิกการยืนยันบัญชีของ ${user.name} แล้ว`;
    setFlash(req, 'success', message);
    return res.redirect('/admin/dashboard');
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการอัปเดตสถานะการยืนยันบัญชี:', error);
    setFlash(req, 'error', 'ไม่สามารถอัปเดตสถานะการยืนยันบัญชีได้');
    return res.redirect('/admin/dashboard');
  }
});

app.post('/admin/users/:id/role', requireRole('admin'), async (req, res) => {
  const userId = Number.parseInt(req.params.id, 10);
  const { role } = req.body;

  if (!Number.isInteger(userId)) {
    setFlash(req, 'error', 'ผู้ใช้ไม่ถูกต้อง');
    return res.redirect('/admin/dashboard');
  }

  if (!allowedRoles.includes(role)) {
    setFlash(req, 'error', 'บทบาทไม่ถูกต้อง');
    return res.redirect('/admin/dashboard');
  }

  if (req.session.user.id === userId && role !== 'admin') {
    setFlash(req, 'error', 'ไม่สามารถปรับลดสิทธิ์ของตนเองได้');
    return res.redirect('/admin/dashboard');
  }

  try {
    const [users] = await pool.query('SELECT id, name, role FROM users WHERE id = ?', [userId]);
    if (!users.length) {
      setFlash(req, 'error', 'ไม่พบผู้ใช้');
      return res.redirect('/admin/dashboard');
    }

    const user = users[0];

    if (user.role === 'admin' && role !== 'admin') {
      const [adminCountRows] = await pool.query(
        'SELECT COUNT(*) AS count FROM users WHERE role = ?',
        ['admin']
      );
      const adminCount = adminCountRows[0]?.count || 0;
      if (adminCount <= 1) {
        setFlash(req, 'error', 'จำเป็นต้องมีผู้ดูแลระบบอย่างน้อย 1 คน');
        return res.redirect('/admin/dashboard');
      }
    }

    if (role === 'admin') {
      await pool.query('UPDATE users SET role = ?, is_approved = 1 WHERE id = ?', [role, userId]);
    } else {
      await pool.query('UPDATE users SET role = ? WHERE id = ?', [role, userId]);
    }

    const roleLabel = role === 'admin' ? 'ผู้ดูแลระบบ' : 'เจ้าหน้าที่';
    setFlash(req, 'success', `อัปเดตบทบาทของ ${user.name} เป็น ${roleLabel} แล้ว`);
    return res.redirect('/admin/dashboard');
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการอัปเดตบทบาท:', error);
    setFlash(req, 'error', 'ไม่สามารถอัปเดตบทบาทได้');
    return res.redirect('/admin/dashboard');
  }
});

app.get('/admin/slider', requireRole('admin'), async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, title, caption, link, image_path, is_active, display_order, created_at, updated_at
       FROM slider_images
       ORDER BY display_order ASC, created_at DESC`
    );
    const sliders = rows.map((row) => ({
      id: row.id,
      title: row.title,
      caption: row.caption,
      link: row.link,
      imagePath: row.image_path,
      isActive: Boolean(row.is_active),
      displayOrder: row.display_order,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    }));

    return res.render('admin-slider', {
      title: 'จัดการภาพสไลด์หน้าแรก',
      sliders
    });
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการโหลดสไลด์:', error);
    setFlash(req, 'error', 'ไม่สามารถโหลดรายการสไลด์ได้');
    return res.redirect('/admin/dashboard');
  }
});

app.get('/admin/slider/new', requireRole('admin'), (req, res) => {
  return res.render('admin-slider-form', {
    title: 'เพิ่มภาพสไลด์',
    mode: 'create',
    slider: null
  });
});

app.post(
  '/admin/slider',
  requireRole('admin'),
  (req, res, next) => {
    sliderImageUploader.single('image')(req, res, (err) => {
      if (err) {
        console.error('เกิดข้อผิดพลาดในการอัปโหลดภาพสไลด์:', err);
        setFlash(req, 'error', err.message || 'ไม่สามารถอัปโหลดภาพสไลด์ได้');
        return res.redirect('/admin/slider/new');
      }
      return next();
    });
  },
  async (req, res) => {
    const { title, caption, link, display_order: displayOrderRaw, is_active: isActiveRaw } = req.body;
    const trimmedTitle = title?.trim();

    if (!trimmedTitle) {
      if (req.file) {
        await removeFileIfExists(toPublicUploadPath(req.file.filename));
      }
      setFlash(req, 'error', 'กรุณาระบุหัวข้อสไลด์');
      return res.redirect('/admin/slider/new');
    }

    if (!req.file) {
      setFlash(req, 'error', 'กรุณาอัปโหลดภาพสำหรับสไลด์');
      return res.redirect('/admin/slider/new');
    }

    const imagePath = toPublicUploadPath(req.file.filename);
    const sliderCaption = caption?.trim() || null;
    const sliderLink = link?.trim() || null;
    const displayOrder = Number.isNaN(Number.parseInt(displayOrderRaw, 10))
      ? 0
      : Number.parseInt(displayOrderRaw, 10);
    const isActive = isActiveRaw ? 1 : 0;

    try {
      await pool.query(
        `INSERT INTO slider_images (title, caption, link, image_path, is_active, display_order)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [trimmedTitle, sliderCaption, sliderLink, imagePath, isActive, displayOrder]
      );
      setFlash(req, 'success', 'เพิ่มสไลด์ใหม่เรียบร้อยแล้ว');
      return res.redirect('/admin/slider');
    } catch (error) {
      console.error('เกิดข้อผิดพลาดในการบันทึกสไลด์:', error);
      await removeFileIfExists(imagePath);
      setFlash(req, 'error', 'ไม่สามารถบันทึกสไลด์ได้');
      return res.redirect('/admin/slider/new');
    }
  }
);

app.get('/admin/slider/:id/edit', requireRole('admin'), async (req, res) => {
  const sliderId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(sliderId)) {
    setFlash(req, 'error', 'รายการสไลด์ไม่ถูกต้อง');
    return res.redirect('/admin/slider');
  }

  try {
    const [rows] = await pool.query(
      'SELECT id, title, caption, link, image_path, is_active, display_order FROM slider_images WHERE id = ?',
      [sliderId]
    );

    if (!rows.length) {
      setFlash(req, 'error', 'ไม่พบรายการสไลด์');
      return res.redirect('/admin/slider');
    }

    const slider = rows[0];
    return res.render('admin-slider-form', {
      title: 'แก้ไขภาพสไลด์',
      mode: 'edit',
      slider: {
        id: slider.id,
        title: slider.title,
        caption: slider.caption,
        link: slider.link,
        imagePath: slider.image_path,
        isActive: Boolean(slider.is_active),
        displayOrder: slider.display_order
      }
    });
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการโหลดสไลด์เพื่อแก้ไข:', error);
    setFlash(req, 'error', 'ไม่สามารถโหลดสไลด์ได้');
    return res.redirect('/admin/slider');
  }
});

app.post(
  '/admin/slider/:id',
  requireRole('admin'),
  (req, res, next) => {
    sliderImageUploader.single('image')(req, res, (err) => {
      if (err) {
        console.error('เกิดข้อผิดพลาดในการอัปโหลดภาพสไลด์:', err);
        setFlash(req, 'error', err.message || 'ไม่สามารถอัปโหลดภาพสไลด์ได้');
        return res.redirect(`/admin/slider/${req.params.id}/edit`);
      }
      return next();
    });
  },
  async (req, res) => {
    const sliderId = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(sliderId)) {
      if (req.file) {
        await removeFileIfExists(toPublicUploadPath(req.file.filename));
      }
      setFlash(req, 'error', 'รายการสไลด์ไม่ถูกต้อง');
      return res.redirect('/admin/slider');
    }

    const { title, caption, link, display_order: displayOrderRaw, is_active: isActiveRaw, removeImage } = req.body;
    const trimmedTitle = title?.trim();

    if (!trimmedTitle) {
      if (req.file) {
        await removeFileIfExists(toPublicUploadPath(req.file.filename));
      }
      setFlash(req, 'error', 'กรุณาระบุหัวข้อสไลด์');
      return res.redirect(`/admin/slider/${sliderId}/edit`);
    }

    const sliderCaption = caption?.trim() || null;
    const sliderLink = link?.trim() || null;
    const displayOrder = Number.isNaN(Number.parseInt(displayOrderRaw, 10))
      ? 0
      : Number.parseInt(displayOrderRaw, 10);
    const isActive = isActiveRaw ? 1 : 0;

    try {
      const [rows] = await pool.query(
        'SELECT image_path FROM slider_images WHERE id = ?',
        [sliderId]
      );

      if (!rows.length) {
        if (req.file) {
          await removeFileIfExists(toPublicUploadPath(req.file.filename));
        }
        setFlash(req, 'error', 'ไม่พบรายการสไลด์');
        return res.redirect('/admin/slider');
      }

      const currentImage = rows[0].image_path;
      let updatedImagePath = currentImage;
      const newImagePath = req.file ? toPublicUploadPath(req.file.filename) : null;
      const filesToRemove = [];

      if (req.file) {
        updatedImagePath = newImagePath;
        if (currentImage) {
          filesToRemove.push(currentImage);
        }
      } else if (removeImage === 'true') {
        setFlash(req, 'error', 'สไลด์จำเป็นต้องมีภาพ กรุณาอัปโหลดภาพใหม่ก่อนยืนยัน');
        return res.redirect(`/admin/slider/${sliderId}/edit`);
      }

      await pool.query(
        `UPDATE slider_images
         SET title = ?, caption = ?, link = ?, image_path = ?, is_active = ?, display_order = ?
         WHERE id = ?`,
        [trimmedTitle, sliderCaption, sliderLink, updatedImagePath, isActive, displayOrder, sliderId]
      );

      await Promise.all(filesToRemove.map((filePath) => removeFileIfExists(filePath)));

      setFlash(req, 'success', 'อัปเดตสไลด์เรียบร้อยแล้ว');
      return res.redirect('/admin/slider');
    } catch (error) {
      console.error('เกิดข้อผิดพลาดในการอัปเดตสไลด์:', error);
      if (req.file) {
        await removeFileIfExists(toPublicUploadPath(req.file.filename));
      }
      setFlash(req, 'error', 'ไม่สามารถอัปเดตสไลด์ได้');
      return res.redirect(`/admin/slider/${sliderId}/edit`);
    }
  }
);

app.post('/admin/slider/:id/delete', requireRole('admin'), async (req, res) => {
  const sliderId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(sliderId)) {
    setFlash(req, 'error', 'รายการสไลด์ไม่ถูกต้อง');
    return res.redirect('/admin/slider');
  }

  try {
    const [rows] = await pool.query('SELECT image_path FROM slider_images WHERE id = ?', [sliderId]);
    if (!rows.length) {
      setFlash(req, 'error', 'ไม่พบรายการสไลด์');
      return res.redirect('/admin/slider');
    }

    const imagePath = rows[0].image_path;
    await pool.query('DELETE FROM slider_images WHERE id = ?', [sliderId]);
    await removeFileIfExists(imagePath);

    setFlash(req, 'success', 'ลบสไลด์เรียบร้อยแล้ว');
    return res.redirect('/admin/slider');
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการลบสไลด์:', error);
    setFlash(req, 'error', 'ไม่สามารถลบสไลด์ได้');
    return res.redirect('/admin/slider');
  }
});

app.get('/admin/settings', requireRole('admin'), async (req, res) => {
  try {
    const siteSettings = await loadSiteSettings({ force: true });
    const [rows] = await pool.query(
      `SELECT id, name, profile_image
       FROM users
       WHERE profile_image IS NOT NULL
       ORDER BY created_at DESC`
    );
    const profileImages = rows
      .filter((row) => row.profile_image)
      .map((row) => ({
        id: row.id,
        name: row.name,
        imagePath: row.profile_image,
        imageUrl: row.profile_image ? `/${row.profile_image}` : null
      }));

    return res.render('admin-settings', {
      title: 'ตั้งค่าระบบ',
      siteSettings,
      profileImages
    });
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการโหลดหน้าตั้งค่าเว็บไซต์:', error);
    setFlash(req, 'error', 'ไม่สามารถโหลดหน้าตั้งค่าเว็บไซต์ได้');
    return res.redirect('/admin/dashboard');
  }
});

app.post(
  '/admin/settings',
  requireRole('admin'),
  (req, res, next) => {
    siteBrandUploader.single('site_logo')(req, res, (err) => {
      if (err) {
        console.error('เกิดข้อผิดพลาดในการอัปโหลดโลโก้เว็บไซต์:', err);
        setFlash(req, 'error', err.message || 'ไม่สามารถอัปโหลดโลโก้เว็บไซต์ได้');
        return res.redirect('/admin/settings');
      }
      return next();
    });
  },
  async (req, res) => {
    const siteNameRaw = req.body?.site_name || '';
    const siteStatusRaw = req.body?.site_status;
    const removeLogo = req.body?.remove_logo === 'true' || req.body?.remove_logo === 'on';
    const siteName = siteNameRaw.trim();

    if (!siteName) {
      if (req.file) {
        await removeFileIfExists(toPublicUploadPath(req.file.filename));
      }
      setFlash(req, 'error', 'กรุณาระบุชื่อเว็บไซต์');
      return res.redirect('/admin/settings');
    }

    const siteStatus = siteStatusRaw === 'closed' ? 'closed' : 'open';
    const uploadedLogoPath = req.file ? toPublicUploadPath(req.file.filename) : null;

    try {
      const currentSettings = await loadSiteSettings({ force: true });
      const updates = [
        { key: 'site_name', value: siteName },
        { key: 'site_status', value: siteStatus }
      ];
      let previousLogoPath = null;

      if (uploadedLogoPath) {
        updates.push({ key: 'site_logo', value: uploadedLogoPath });
        if (currentSettings.siteLogoPath) {
          previousLogoPath = currentSettings.siteLogoPath;
        }
      } else if (removeLogo && currentSettings.siteLogoPath) {
        updates.push({ key: 'site_logo', value: '' });
        previousLogoPath = currentSettings.siteLogoPath;
      }

      await updateSiteSettingsBulk(updates);

      if (previousLogoPath && previousLogoPath !== uploadedLogoPath) {
        await removeFileIfExists(previousLogoPath);
      }

      setFlash(req, 'success', 'บันทึกการตั้งค่าเว็บไซต์เรียบร้อยแล้ว');
    } catch (error) {
      console.error('เกิดข้อผิดพลาดในการอัปเดตการตั้งค่าเว็บไซต์:', error);
      if (uploadedLogoPath) {
        await removeFileIfExists(uploadedLogoPath);
      }
      setFlash(req, 'error', 'ไม่สามารถบันทึกการตั้งค่าเว็บไซต์ได้');
    }

    return res.redirect('/admin/settings');
  }
);

app.get('/admin/news', requireRole('admin'), async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT
         n.id,
         n.title,
         n.slug,
         n.is_published,
         n.created_at,
         n.updated_at,
         (SELECT COUNT(*) FROM news_files nf WHERE nf.news_id = n.id) AS attachment_count
       FROM news n
       ORDER BY n.created_at DESC`
    );
    const articles = rows.map((row) => ({
      id: row.id,
      title: row.title,
      slug: row.slug,
      isPublished: Boolean(row.is_published),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      attachmentCount: Number.parseInt(row.attachment_count, 10) || 0
    }));

    return res.render('admin-news', {
      title: 'จัดการข่าวประชาสัมพันธ์',
      articles
    });
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการโหลดข่าวประชาสัมพันธ์:', error);
    setFlash(req, 'error', 'ไม่สามารถโหลดรายการข่าวได้');
    return res.redirect('/admin/dashboard');
  }
});

app.get('/admin/news/new', requireRole('admin'), async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id, name FROM news_categories WHERE is_active = 1 ORDER BY display_order ASC, name ASC'
    );
    const categories = rows.map((row) => ({
      id: row.id,
      name: row.name
    }));

  return res.render('admin-news-form', {
    title: 'สร้างข่าวประชาสัมพันธ์',
    mode: 'create',
      article: null,
      categories
  });
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการโหลดหมวดหมู่ข่าว:', error);
    setFlash(req, 'error', 'ไม่สามารถโหลดหมวดหมู่ข่าวได้');
    return res.redirect('/admin/news');
  }
});

app.post(
  '/admin/news',
  requireRole('admin'),
  composeNewsUploads(() => '/admin/news/new'),
  async (req, res) => {
    const { title, content, image_caption: imageCaptionRaw, is_published: isPublishedRaw, category_id: categoryIdRaw } = req.body;
    const trimmedTitle = title?.trim();
    const trimmedContent = content?.trim();
    const categoryId = Number.parseInt(categoryIdRaw, 10);

    if (!trimmedTitle || !trimmedContent) {
      await cleanupUploadedFiles(req.files);
      setFlash(req, 'error', 'กรุณากรอกหัวข้อและเนื้อหาของข่าว');
      return res.redirect('/admin/news/new');
    }

    const imageFile = req.files?.image?.[0] || null;
    const attachments = req.files?.attachments || [];
    const imagePath = imageFile ? toPublicUploadPath(imageFile.filename) : null;
    const authorId = req.session.user?.id || null;
    const imageCaption = imageCaptionRaw?.trim() ? imageCaptionRaw.trim() : null;
    const isPublished = isPublishedRaw ? 1 : 0;

    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();

      let slug = generateNewsSlug(trimmedTitle);
      let newsId;
      let attempt = 0;

      while (!newsId && attempt < 3) {
        attempt += 1;
        try {
          const [result] = await connection.query(
            'INSERT INTO news (title, slug, author_id, content, image_path, image_caption, is_published, category_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [trimmedTitle, slug, authorId, trimmedContent, imagePath, imageCaption, isPublished, Number.isInteger(categoryId) ? categoryId : null]
          );
          newsId = result.insertId;
        } catch (error) {
          if (error.code === 'ER_DUP_ENTRY' && attempt < 3) {
            slug = generateNewsSlug(`${trimmedTitle}-${Math.round(Math.random() * 1e6)}`);
          } else {
            throw error;
          }
        }
      }

      if (!newsId) {
        throw new Error('ไม่สามารถสร้างข่าวประชาสัมพันธ์ได้');
      }

      if (attachments.length) {
        const attachmentValues = attachments.map((file) => [
          newsId,
          toPublicUploadPath(file.filename),
          decodeFilename(file.originalname || file.filename),
          file.size || 0
        ]);
        await connection.query(
          'INSERT INTO news_files (news_id, file_path, original_name, file_size) VALUES ?',
          [attachmentValues]
        );
      }

      await connection.commit();
      setFlash(req, 'success', 'บันทึกข่าวประชาสัมพันธ์เรียบร้อยแล้ว');
      return res.redirect('/admin/news');
    } catch (error) {
      await connection.rollback();
      console.error('เกิดข้อผิดพลาดในการบันทึกข่าวประชาสัมพันธ์:', error);
      if (imagePath) {
        await removeFileIfExists(imagePath);
      }
      await cleanupUploadedFiles(attachments);
      setFlash(req, 'error', 'ไม่สามารถบันทึกข่าวประชาสัมพันธ์ได้');
      return res.redirect('/admin/news/new');
    } finally {
      connection.release();
    }
  }
);

app.get('/admin/news/:id/edit', requireRole('admin'), async (req, res) => {
  const newsId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(newsId)) {
    setFlash(req, 'error', 'รายการข่าวไม่ถูกต้อง');
    return res.redirect('/admin/news');
  }

  try {
    const [rows] = await pool.query(
      'SELECT id, title, content, image_path, image_caption, is_published, category_id FROM news WHERE id = ?',
      [newsId]
    );

    if (!rows.length) {
      setFlash(req, 'error', 'ไม่พบรายการข่าว');
      return res.redirect('/admin/news');
    }

    const article = rows[0];
    const [fileRows] = await pool.query(
      'SELECT id, original_name, file_path, file_size, created_at FROM news_files WHERE news_id = ? ORDER BY created_at ASC',
      [newsId]
    );
    const attachments = fileRows.map((file) => ({
      id: file.id,
      originalName: file.original_name,
      filePath: file.file_path,
      fileSize: file.file_size,
      createdAt: file.created_at
    }));

    const [categoryRows] = await pool.query(
      'SELECT id, name FROM news_categories WHERE is_active = 1 ORDER BY display_order ASC, name ASC'
    );
    const categories = categoryRows.map((row) => ({
      id: row.id,
      name: row.name
    }));

    return res.render('admin-news-form', {
      title: 'แก้ไขข่าวประชาสัมพันธ์',
      mode: 'edit',
      article: {
        id: article.id,
        title: article.title,
        content: article.content,
        imagePath: article.image_path,
        imageCaption: article.image_caption,
        isPublished: Boolean(article.is_published),
        categoryId: article.category_id,
        attachments
      },
      categories
    });
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการโหลดข่าวเพื่อแก้ไข:', error);
    setFlash(req, 'error', 'ไม่สามารถโหลดข่าวได้');
    return res.redirect('/admin/news');
  }
});

app.post(
  '/admin/news/:id',
  requireRole('admin'),
  composeNewsUploads((req) => `/admin/news/${req.params.id}/edit`),
  async (req, res) => {
    const newsId = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(newsId)) {
      await cleanupUploadedFiles(req.files);
      setFlash(req, 'error', 'รายการข่าวไม่ถูกต้อง');
      return res.redirect('/admin/news');
    }

    const { title, content, image_caption: imageCaptionRaw, is_published: isPublishedRaw, removeImage, category_id: categoryIdRaw } = req.body;

    const trimmedTitle = title?.trim();
    const trimmedContent = content?.trim();
    const categoryId = Number.parseInt(categoryIdRaw, 10);
    if (!trimmedTitle || !trimmedContent) {
      await cleanupUploadedFiles(req.files);
      setFlash(req, 'error', 'กรุณากรอกหัวข้อและเนื้อหาของข่าว');
      return res.redirect(`/admin/news/${newsId}/edit`);
    }

    const imageFile = req.files?.image?.[0] || null;
    const attachments = req.files?.attachments || [];
    const imageCaption = imageCaptionRaw?.trim() ? imageCaptionRaw.trim() : null;
    const isPublished = isPublishedRaw ? 1 : 0;
    let filesToDelete = [];
    let committed = false;
    const newImagePath = imageFile ? toPublicUploadPath(imageFile.filename) : null;

    const connection = await pool.getConnection();
    try {
      const [rows] = await connection.query(
        'SELECT image_path FROM news WHERE id = ?',
        [newsId]
      );

      if (!rows.length) {
        await cleanupUploadedFiles(attachments);
        if (newImagePath) {
          await removeFileIfExists(newImagePath);
        }
        setFlash(req, 'error', 'ไม่พบรายการข่าว');
        return res.redirect('/admin/news');
      }

      const existingImagePath = rows[0].image_path;
      let updatedImagePath = existingImagePath;

      if (imageFile) {
        updatedImagePath = newImagePath;
        if (existingImagePath) {
          filesToDelete.push(existingImagePath);
        }
      } else if (removeImage === 'true') {
        if (existingImagePath) {
          filesToDelete.push(existingImagePath);
        }
        updatedImagePath = null;
      }

      let removeAttachmentIds = req.body.removeAttachments || [];
      if (!Array.isArray(removeAttachmentIds)) {
        removeAttachmentIds = removeAttachmentIds ? [removeAttachmentIds] : [];
      }
      const attachmentIds = removeAttachmentIds
        .map((id) => Number.parseInt(id, 10))
        .filter((id) => Number.isInteger(id));

      await connection.beginTransaction();

      await connection.query(
        'UPDATE news SET title = ?, content = ?, image_path = ?, image_caption = ?, is_published = ?, category_id = ? WHERE id = ?',
        [
          trimmedTitle,
          trimmedContent,
          updatedImagePath,
          imageCaption,
          isPublished,
          Number.isInteger(categoryId) ? categoryId : null,
          newsId
        ]
      );

      if (attachments.length) {
        const attachmentValues = attachments.map((file) => [
          newsId,
          toPublicUploadPath(file.filename),
          decodeFilename(file.originalname || file.filename),
          file.size || 0
        ]);
        await connection.query(
          'INSERT INTO news_files (news_id, file_path, original_name, file_size) VALUES ?',
          [attachmentValues]
        );
      }

      if (attachmentIds.length) {
        const [existingAttachments] = await connection.query(
          'SELECT id, file_path FROM news_files WHERE news_id = ? AND id IN (?)',
          [newsId, attachmentIds]
        );
        if (existingAttachments.length) {
          filesToDelete = filesToDelete.concat(
            existingAttachments.map((attachment) => attachment.file_path)
          );
          await connection.query(
            'DELETE FROM news_files WHERE news_id = ? AND id IN (?)',
            [newsId, attachmentIds]
          );
        }
      }

      await connection.commit();
      committed = true;
      setFlash(req, 'success', 'อัปเดตข่าวประชาสัมพันธ์เรียบร้อยแล้ว');
      return res.redirect('/admin/news');
    } catch (error) {
      await connection.rollback();
      console.error('เกิดข้อผิดพลาดในการอัปเดตข่าวประชาสัมพันธ์:', error);
      await cleanupUploadedFiles(attachments);
      if (newImagePath) {
        await removeFileIfExists(newImagePath);
      }
      setFlash(req, 'error', 'ไม่สามารถอัปเดตข่าวได้');
      return res.redirect(`/admin/news/${newsId}/edit`);
    } finally {
      connection.release();
      if (committed && filesToDelete.length) {
        await Promise.all(
          filesToDelete.map((filePath) => removeFileIfExists(filePath))
        );
      }
    }
  }
);

app.post('/admin/news/:id/delete', requireRole('admin'), async (req, res) => {
  const newsId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(newsId)) {
    setFlash(req, 'error', 'รายการข่าวไม่ถูกต้อง');
    return res.redirect('/admin/news');
  }

  try {
    const [rows] = await pool.query(
      'SELECT image_path FROM news WHERE id = ?',
      [newsId]
    );

    if (!rows.length) {
      setFlash(req, 'error', 'ไม่พบรายการข่าว');
      return res.redirect('/admin/news');
    }

    const imagePath = rows[0].image_path;
    const [attachmentRows] = await pool.query(
      'SELECT file_path FROM news_files WHERE news_id = ?',
      [newsId]
    );
    const attachmentPaths = attachmentRows.map((row) => row.file_path);
    await pool.query('DELETE FROM news WHERE id = ?', [newsId]);
    await removeFileIfExists(imagePath);
    if (attachmentPaths.length) {
      await Promise.all(
        attachmentPaths.map((filePath) => removeFileIfExists(filePath))
      );
    }

    setFlash(req, 'success', 'ลบข่าวประชาสัมพันธ์เรียบร้อยแล้ว');
    return res.redirect('/admin/news');
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการลบข่าวประชาสัมพันธ์:', error);
    setFlash(req, 'error', 'ไม่สามารถลบข่าวได้');
    return res.redirect('/admin/news');
  }
});

// Route สำหรับดาวน์โหลดไฟล์แนบของข่าว - ต้องเป็นสมาชิกเท่านั้น (ต้องอยู่ก่อน route /news/:slug)
app.get('/news/files/:fileId/download', async (req, res) => {
  // ตรวจสอบ authentication ก่อน
  if (!req.session.user) {
    setFlash(req, 'error', 'กรุณาเข้าสู่ระบบก่อน');
    return res.redirect('/login');
  }

  const fileId = Number.parseInt(req.params.fileId, 10);
  const userRole = req.session.user?.role;

  // ตรวจสอบว่าผู้ใช้เป็นสมาชิก (admin หรือ staff)
  if (!['admin', 'staff'].includes(userRole)) {
    setFlash(req, 'error', 'ต้องเป็นสมาชิกถึงจะสามารถดาวน์โหลดไฟล์ได้');
    const referer = req.get('Referer') || '/';
    return res.redirect(referer);
  }

  if (!Number.isInteger(fileId)) {
    setFlash(req, 'error', 'ไฟล์ไม่ถูกต้อง');
    const referer = req.get('Referer') || '/';
    return res.redirect(referer);
  }

  try {
    // ดึงข้อมูลไฟล์จากฐานข้อมูลพร้อม slug ของข่าว
    const [fileRows] = await pool.query(
      `SELECT nf.id, nf.file_path, nf.original_name, n.id AS news_id, n.slug, n.is_published
       FROM news_files nf
       INNER JOIN news n ON nf.news_id = n.id
       WHERE nf.id = ?`,
      [fileId]
    );

    if (!fileRows.length) {
      setFlash(req, 'error', 'ไม่พบไฟล์ที่ต้องการ');
      const referer = req.get('Referer') || '/';
      return res.redirect(referer);
    }

    const fileData = fileRows[0];
    const newsSlug = fileData.slug;
    
    // ตรวจสอบว่าข่าวถูกเผยแพร่แล้ว หรือผู้ใช้เป็น admin
    const isPublished = Boolean(fileData.is_published);
    const isAdmin = userRole === 'admin';

    if (!isPublished && !isAdmin) {
      setFlash(req, 'error', 'ไม่สามารถดาวน์โหลดไฟล์นี้ได้');
      return res.redirect(`/news/${newsSlug}`);
    }

    // ตรวจสอบว่าไฟล์มีอยู่จริง
    const filePath = path.join(__dirname, 'public', fileData.file_path);
    
    if (!fs.existsSync(filePath)) {
      setFlash(req, 'error', 'ไม่พบไฟล์ที่ต้องการ');
      return res.redirect(`/news/${newsSlug}`);
    }

    // ส่งไฟล์ให้ดาวน์โหลด
    const originalName = fileData.original_name || path.basename(fileData.file_path);
    res.download(filePath, originalName, (err) => {
      if (err) {
        console.error('เกิดข้อผิดพลาดในการดาวน์โหลดไฟล์:', err);
        if (!res.headersSent) {
          setFlash(req, 'error', 'ไม่สามารถดาวน์โหลดไฟล์ได้');
          return res.redirect(`/news/${newsSlug}`);
        }
      }
    });
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการดาวน์โหลดไฟล์:', error);
    setFlash(req, 'error', 'ไม่สามารถดาวน์โหลดไฟล์ได้');
    const referer = req.get('Referer') || '/';
    return res.redirect(referer);
  }
});

app.get('/news/:slug', async (req, res) => {
  const { slug } = req.params;

  try {
    const [rows] = await pool.query(
      `SELECT
         n.id,
         n.title,
         n.content,
         n.image_path,
         n.image_caption,
         n.is_published,
         n.created_at,
         n.updated_at,
         u.name AS author_name,
         u.profile_image AS author_image,
         u.position AS author_position,
         u.affiliation AS author_affiliation,
         u.email AS author_email
       FROM news n
       LEFT JOIN users u ON n.author_id = u.id
       WHERE n.slug = ?`,
      [slug]
    );

    if (!rows.length) {
      return res.status(404).render('404', { title: 'ไม่พบหน้านี้' });
    }

    const article = rows[0];
    const isPublished = Boolean(article.is_published);
    const isAdmin = req.session.user?.role === 'admin';

    if (!isPublished && !isAdmin) {
      return res.status(404).render('404', { title: 'ไม่พบหน้านี้' });
    }

    const [attachmentRows] = await pool.query(
      'SELECT id, original_name, file_path, file_size, created_at FROM news_files WHERE news_id = ? ORDER BY created_at ASC',
      [article.id]
    );
    const attachments = attachmentRows.map((file) => ({
      id: file.id,
      originalName: file.original_name,
      filePath: file.file_path,
      fileSize: file.file_size,
      createdAt: file.created_at
    }));

    const [likeCountRows] = await pool.query(
      'SELECT COUNT(*) AS like_count FROM news_likes WHERE news_id = ?',
      [article.id]
    );
    const likeCount = likeCountRows[0]?.like_count || 0;

    let hasLiked = false;
    if (req.session.user) {
      const [userLikeRows] = await pool.query(
        'SELECT 1 FROM news_likes WHERE news_id = ? AND user_id = ?',
        [article.id, req.session.user.id]
      );
      hasLiked = userLikeRows.length > 0;
    }

    return res.render('news-detail', {
      title: article.title,
      article: {
        id: article.id,
        title: article.title,
        content: article.content,
        imagePath: article.image_path,
        imageCaption: article.image_caption,
        createdAt: article.created_at,
        updatedAt: article.updated_at,
        isPublished,
        author: {
          name: article.author_name || 'ทีมผู้ดูแลระบบ',
          image: article.author_image,
          position: article.author_position,
          affiliation: article.author_affiliation,
          email: article.author_email
        },
        attachments,
        likeCount,
        hasLiked
      },
      canEdit: isAdmin
    });
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการแสดงข่าว:', error);
    setFlash(req, 'error', 'ไม่สามารถเปิดข่าวประชาสัมพันธ์ได้');
    return res.redirect('/');
  }
});

app.post('/news/:id/like', requireAuth, async (req, res) => {
  const newsId = Number.parseInt(req.params.id, 10);
  const userId = req.session.user.id;

  if (!Number.isInteger(newsId)) {
    return res.status(400).json({ success: false, message: 'รหัสข่าวไม่ถูกต้อง' });
  }

  try {
    const [newsRows] = await pool.query('SELECT id FROM news WHERE id = ?', [newsId]);
    if (!newsRows.length) {
      return res.status(404).json({ success: false, message: 'ไม่พบข่าวที่ต้องการ' });
    }

    const [existingLike] = await pool.query(
      'SELECT 1 FROM news_likes WHERE news_id = ? AND user_id = ?',
      [newsId, userId]
    );

    let message;
    if (existingLike.length > 0) {
      await pool.query('DELETE FROM news_likes WHERE news_id = ? AND user_id = ?', [newsId, userId]);
      message = 'ยกเลิกการถูกใจแล้ว';
    } else {
      await pool.query('INSERT INTO news_likes (news_id, user_id) VALUES (?, ?)', [newsId, userId]);
      message = 'ถูกใจแล้ว';
    }

    const [likeCountRows] = await pool.query(
      'SELECT COUNT(*) AS like_count FROM news_likes WHERE news_id = ?',
      [newsId]
    );
    const newLikeCount = likeCountRows[0]?.like_count || 0;

    return res.json({ success: true, message, likeCount: newLikeCount, hasLiked: existingLike.length === 0 });
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการจัดการการถูกใจ:', error);
    return res.status(500).json({ success: false, message: 'ไม่สามารถดำเนินการได้' });
  }
});

app.get('/staff/dashboard', requireAuth, (req, res) => {
  if (!['admin', 'staff'].includes(req.session.user.role)) {
    setFlash(req, 'error', 'คุณไม่มีสิทธิ์เข้าถึงหน้านี้');
    return res.redirect('/');
  }

  return res.render('staff-dashboard', {
    title: 'แดชบอร์ดเจ้าหน้าที่'
  });
});

// Menu Categories Routes
app.get('/admin/menu-categories', requireRole('admin'), async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT 
         mc.id, 
         mc.name, 
         mc.description, 
         mc.icon, 
         mc.color, 
         mc.is_active, 
         mc.display_order, 
         mc.created_at, 
         mc.updated_at,
         COUNT(mi.id) as item_count
       FROM menu_categories mc
       LEFT JOIN menu_items mi ON mc.id = mi.category_id AND mi.is_active = 1
       GROUP BY mc.id
       ORDER BY mc.display_order ASC, mc.created_at DESC`
    );
    
    const categories = rows.map((row) => ({
      id: row.id,
      name: row.name,
      description: row.description,
      icon: row.icon,
      color: row.color,
      isActive: Boolean(row.is_active),
      displayOrder: row.display_order,
      itemCount: Number.parseInt(row.item_count, 10) || 0,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    }));

    return res.render('admin-menu-categories', {
      title: 'จัดการหมวดเมนู',
      categories
    });
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการโหลดหมวดเมนู:', error);
    setFlash(req, 'error', 'ไม่สามารถโหลดรายการหมวดเมนูได้');
    return res.redirect('/admin/dashboard');
  }
});

app.get('/admin/menu-categories/new', requireRole('admin'), (req, res) => {
  return res.render('admin-menu-category-form', {
    title: 'เพิ่มหมวดเมนู',
    mode: 'create',
    category: null
  });
});

app.post('/admin/menu-categories', requireRole('admin'), async (req, res) => {
  const { name, description, icon, color, display_order: displayOrderRaw, is_active: isActiveRaw } = req.body;
  const trimmedName = name?.trim();
  const trimmedDescription = description?.trim() || null;
  const trimmedIcon = icon?.trim() || null;
  const trimmedColor = color?.trim() || 'primary';
  const displayOrder = Number.isNaN(Number.parseInt(displayOrderRaw, 10)) ? 0 : Number.parseInt(displayOrderRaw, 10);
  const isActive = isActiveRaw ? 1 : 0;

  if (!trimmedName) {
    setFlash(req, 'error', 'กรุณาระบุชื่อหมวดเมนู');
    return res.redirect('/admin/menu-categories/new');
  }

  try {
    await pool.query(
      `INSERT INTO menu_categories (name, description, icon, color, is_active, display_order)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [trimmedName, trimmedDescription, trimmedIcon, trimmedColor, isActive, displayOrder]
    );
    setFlash(req, 'success', 'เพิ่มหมวดเมนูใหม่เรียบร้อยแล้ว');
    return res.redirect('/admin/menu-categories');
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการบันทึกหมวดเมนู:', error);
    setFlash(req, 'error', 'ไม่สามารถบันทึกหมวดเมนูได้');
    return res.redirect('/admin/menu-categories/new');
  }
});

app.get('/admin/menu-categories/:id/edit', requireRole('admin'), async (req, res) => {
  const categoryId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(categoryId)) {
    setFlash(req, 'error', 'หมวดเมนูไม่ถูกต้อง');
    return res.redirect('/admin/menu-categories');
  }

  try {
    const [rows] = await pool.query(
      'SELECT id, name, description, icon, color, is_active, display_order FROM menu_categories WHERE id = ?',
      [categoryId]
    );

    if (!rows.length) {
      setFlash(req, 'error', 'ไม่พบหมวดเมนู');
      return res.redirect('/admin/menu-categories');
    }

    const category = rows[0];
    return res.render('admin-menu-category-form', {
      title: 'แก้ไขหมวดเมนู',
      mode: 'edit',
      category: {
        id: category.id,
        name: category.name,
        description: category.description,
        icon: category.icon,
        color: category.color,
        isActive: Boolean(category.is_active),
        displayOrder: category.display_order
      }
    });
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการโหลดหมวดเมนูเพื่อแก้ไข:', error);
    setFlash(req, 'error', 'ไม่สามารถโหลดหมวดเมนูได้');
    return res.redirect('/admin/menu-categories');
  }
});

app.post('/admin/menu-categories/:id', requireRole('admin'), async (req, res) => {
  const categoryId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(categoryId)) {
    setFlash(req, 'error', 'หมวดเมนูไม่ถูกต้อง');
    return res.redirect('/admin/menu-categories');
  }

  const { name, description, icon, color, display_order: displayOrderRaw, is_active: isActiveRaw } = req.body;
  const trimmedName = name?.trim();
  const trimmedDescription = description?.trim() || null;
  const trimmedIcon = icon?.trim() || null;
  const trimmedColor = color?.trim() || 'primary';
  const displayOrder = Number.isNaN(Number.parseInt(displayOrderRaw, 10)) ? 0 : Number.parseInt(displayOrderRaw, 10);
  const isActive = isActiveRaw ? 1 : 0;

  if (!trimmedName) {
    setFlash(req, 'error', 'กรุณาระบุชื่อหมวดเมนู');
    return res.redirect(`/admin/menu-categories/${categoryId}/edit`);
  }

  try {
    const [rows] = await pool.query('SELECT id FROM menu_categories WHERE id = ?', [categoryId]);
    if (!rows.length) {
      setFlash(req, 'error', 'ไม่พบหมวดเมนู');
      return res.redirect('/admin/menu-categories');
    }

    await pool.query(
      `UPDATE menu_categories 
       SET name = ?, description = ?, icon = ?, color = ?, is_active = ?, display_order = ?
       WHERE id = ?`,
      [trimmedName, trimmedDescription, trimmedIcon, trimmedColor, isActive, displayOrder, categoryId]
    );

    setFlash(req, 'success', 'อัปเดตหมวดเมนูเรียบร้อยแล้ว');
    return res.redirect('/admin/menu-categories');
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการอัปเดตหมวดเมนู:', error);
    setFlash(req, 'error', 'ไม่สามารถอัปเดตหมวดเมนูได้');
    return res.redirect(`/admin/menu-categories/${categoryId}/edit`);
  }
});

app.post('/admin/menu-categories/:id/delete', requireRole('admin'), async (req, res) => {
  const categoryId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(categoryId)) {
    setFlash(req, 'error', 'หมวดเมนูไม่ถูกต้อง');
    return res.redirect('/admin/menu-categories');
  }

  try {
    const [rows] = await pool.query('SELECT id FROM menu_categories WHERE id = ?', [categoryId]);
    if (!rows.length) {
      setFlash(req, 'error', 'ไม่พบหมวดเมนู');
      return res.redirect('/admin/menu-categories');
    }

    await pool.query('DELETE FROM menu_categories WHERE id = ?', [categoryId]);
    setFlash(req, 'success', 'ลบหมวดเมนูเรียบร้อยแล้ว');
    return res.redirect('/admin/menu-categories');
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการลบหมวดเมนู:', error);
    setFlash(req, 'error', 'ไม่สามารถลบหมวดเมนูได้');
    return res.redirect('/admin/menu-categories');
  }
});

// Menu Items Routes
app.get('/admin/menu-items', requireRole('admin'), async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT 
         mi.id, 
         mi.title, 
         mi.description, 
         mi.link, 
         mi.image_path, 
         mi.is_active, 
         mi.display_order, 
         mi.created_at, 
         mi.updated_at,
         mc.name as category_name,
         mc.color as category_color
       FROM menu_items mi
       LEFT JOIN menu_categories mc ON mi.category_id = mc.id
       ORDER BY mc.display_order ASC, mi.display_order ASC, mi.created_at DESC`
    );
    
    const items = rows.map((row) => ({
      id: row.id,
      title: row.title,
      description: row.description,
      link: row.link,
      imagePath: row.image_path,
      isActive: Boolean(row.is_active),
      displayOrder: row.display_order,
      categoryName: row.category_name,
      categoryColor: row.category_color,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    }));

    return res.render('admin-menu-items', {
      title: 'จัดการเมนูย่อ',
      items
    });
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการโหลดเมนูย่อ:', error);
    setFlash(req, 'error', 'ไม่สามารถโหลดรายการเมนูย่อได้');
    return res.redirect('/admin/dashboard');
  }
});

app.get('/admin/menu-items/new', requireRole('admin'), async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id, name FROM menu_categories WHERE is_active = 1 ORDER BY display_order ASC, name ASC'
    );
    const categories = rows.map((row) => ({
      id: row.id,
      name: row.name
    }));

    return res.render('admin-menu-item-form', {
      title: 'เพิ่มเมนูย่อ',
      mode: 'create',
      item: null,
      categories
    });
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการโหลดหมวดเมนู:', error);
    setFlash(req, 'error', 'ไม่สามารถโหลดหมวดเมนูได้');
    return res.redirect('/admin/menu-items');
  }
});

app.post(
  '/admin/menu-items',
  requireRole('admin'),
  (req, res, next) => {
    sliderImageUploader.single('image')(req, res, (err) => {
      if (err) {
        console.error('เกิดข้อผิดพลาดในการอัปโหลดรูปเมนู:', err);
        setFlash(req, 'error', err.message || 'ไม่สามารถอัปโหลดรูปเมนูได้');
        return res.redirect('/admin/menu-items/new');
      }
      return next();
    });
  },
  async (req, res) => {
    const { title, description, link, category_id: categoryIdRaw, display_order: displayOrderRaw, is_active: isActiveRaw } = req.body;
    const trimmedTitle = title?.trim();
    const trimmedDescription = description?.trim() || null;
    const trimmedLink = link?.trim() || null;
    const categoryId = Number.parseInt(categoryIdRaw, 10);
    const displayOrder = Number.isNaN(Number.parseInt(displayOrderRaw, 10)) ? 0 : Number.parseInt(displayOrderRaw, 10);
    const isActive = isActiveRaw ? 1 : 0;

    if (!trimmedTitle) {
      if (req.file) {
        await removeFileIfExists(toPublicUploadPath(req.file.filename));
      }
      setFlash(req, 'error', 'กรุณาระบุชื่อเมนูย่อ');
      return res.redirect('/admin/menu-items/new');
    }

    if (!Number.isInteger(categoryId)) {
      if (req.file) {
        await removeFileIfExists(toPublicUploadPath(req.file.filename));
      }
      setFlash(req, 'error', 'กรุณาเลือกหมวดเมนู');
      return res.redirect('/admin/menu-items/new');
    }

    const imagePath = req.file ? toPublicUploadPath(req.file.filename) : null;

    try {
      await pool.query(
        `INSERT INTO menu_items (category_id, title, description, link, image_path, is_active, display_order)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [categoryId, trimmedTitle, trimmedDescription, trimmedLink, imagePath, isActive, displayOrder]
      );
      setFlash(req, 'success', 'เพิ่มเมนูย่อใหม่เรียบร้อยแล้ว');
      return res.redirect('/admin/menu-items');
    } catch (error) {
      console.error('เกิดข้อผิดพลาดในการบันทึกเมนูย่อ:', error);
      if (imagePath) {
        await removeFileIfExists(imagePath);
      }
      setFlash(req, 'error', 'ไม่สามารถบันทึกเมนูย่อได้');
      return res.redirect('/admin/menu-items/new');
    }
  }
);

app.get('/admin/menu-items/:id/edit', requireRole('admin'), async (req, res) => {
  const itemId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(itemId)) {
    setFlash(req, 'error', 'เมนูย่อไม่ถูกต้อง');
    return res.redirect('/admin/menu-items');
  }

  try {
    const [rows] = await pool.query(
      'SELECT id, title, description, link, image_path, category_id, is_active, display_order FROM menu_items WHERE id = ?',
      [itemId]
    );

    if (!rows.length) {
      setFlash(req, 'error', 'ไม่พบเมนูย่อ');
      return res.redirect('/admin/menu-items');
    }

    const item = rows[0];
    const [categoryRows] = await pool.query(
      'SELECT id, name FROM menu_categories WHERE is_active = 1 ORDER BY display_order ASC, name ASC'
    );
    const categories = categoryRows.map((row) => ({
      id: row.id,
      name: row.name
    }));

    return res.render('admin-menu-item-form', {
      title: 'แก้ไขเมนูย่อ',
      mode: 'edit',
      item: {
        id: item.id,
        title: item.title,
        description: item.description,
        link: item.link,
        imagePath: item.image_path,
        categoryId: item.category_id,
        isActive: Boolean(item.is_active),
        displayOrder: item.display_order
      },
      categories
    });
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการโหลดเมนูย่อเพื่อแก้ไข:', error);
    setFlash(req, 'error', 'ไม่สามารถโหลดเมนูย่อได้');
    return res.redirect('/admin/menu-items');
  }
});

app.post(
  '/admin/menu-items/:id',
  requireRole('admin'),
  (req, res, next) => {
    sliderImageUploader.single('image')(req, res, (err) => {
      if (err) {
        console.error('เกิดข้อผิดพลาดในการอัปโหลดรูปเมนู:', err);
        setFlash(req, 'error', err.message || 'ไม่สามารถอัปโหลดรูปเมนูได้');
        return res.redirect(`/admin/menu-items/${req.params.id}/edit`);
      }
      return next();
    });
  },
  async (req, res) => {
    const itemId = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(itemId)) {
      if (req.file) {
        await removeFileIfExists(toPublicUploadPath(req.file.filename));
      }
      setFlash(req, 'error', 'เมนูย่อไม่ถูกต้อง');
      return res.redirect('/admin/menu-items');
    }

    const { title, description, link, category_id: categoryIdRaw, display_order: displayOrderRaw, is_active: isActiveRaw, removeImage } = req.body;
    const trimmedTitle = title?.trim();
    const trimmedDescription = description?.trim() || null;
    const trimmedLink = link?.trim() || null;
    const categoryId = Number.parseInt(categoryIdRaw, 10);
    const displayOrder = Number.isNaN(Number.parseInt(displayOrderRaw, 10)) ? 0 : Number.parseInt(displayOrderRaw, 10);
    const isActive = isActiveRaw ? 1 : 0;

    if (!trimmedTitle) {
      if (req.file) {
        await removeFileIfExists(toPublicUploadPath(req.file.filename));
      }
      setFlash(req, 'error', 'กรุณาระบุชื่อเมนูย่อ');
      return res.redirect(`/admin/menu-items/${itemId}/edit`);
    }

    if (!Number.isInteger(categoryId)) {
      if (req.file) {
        await removeFileIfExists(toPublicUploadPath(req.file.filename));
      }
      setFlash(req, 'error', 'กรุณาเลือกหมวดเมนู');
      return res.redirect(`/admin/menu-items/${itemId}/edit`);
    }

    try {
      const [rows] = await pool.query('SELECT image_path FROM menu_items WHERE id = ?', [itemId]);
      if (!rows.length) {
        if (req.file) {
          await removeFileIfExists(toPublicUploadPath(req.file.filename));
        }
        setFlash(req, 'error', 'ไม่พบเมนูย่อ');
        return res.redirect('/admin/menu-items');
      }

      const currentImagePath = rows[0].image_path;
      let updatedImagePath = currentImagePath;
      const newImagePath = req.file ? toPublicUploadPath(req.file.filename) : null;
      const filesToRemove = [];

      if (req.file) {
        updatedImagePath = newImagePath;
        if (currentImagePath) {
          filesToRemove.push(currentImagePath);
        }
      } else if (removeImage === 'true') {
        if (currentImagePath) {
          filesToRemove.push(currentImagePath);
        }
        updatedImagePath = null;
      }

      await pool.query(
        `UPDATE menu_items 
         SET title = ?, description = ?, link = ?, category_id = ?, image_path = ?, is_active = ?, display_order = ?
         WHERE id = ?`,
        [trimmedTitle, trimmedDescription, trimmedLink, categoryId, updatedImagePath, isActive, displayOrder, itemId]
      );

      await Promise.all(filesToRemove.map((filePath) => removeFileIfExists(filePath)));

      setFlash(req, 'success', 'อัปเดตเมนูย่อเรียบร้อยแล้ว');
      return res.redirect('/admin/menu-items');
    } catch (error) {
      console.error('เกิดข้อผิดพลาดในการอัปเดตเมนูย่อ:', error);
      if (req.file) {
        await removeFileIfExists(toPublicUploadPath(req.file.filename));
      }
      setFlash(req, 'error', 'ไม่สามารถอัปเดตเมนูย่อได้');
      return res.redirect(`/admin/menu-items/${itemId}/edit`);
    }
  }
);

app.post('/admin/menu-items/:id/delete', requireRole('admin'), async (req, res) => {
  const itemId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(itemId)) {
    setFlash(req, 'error', 'เมนูย่อไม่ถูกต้อง');
    return res.redirect('/admin/menu-items');
  }

  try {
    const [rows] = await pool.query('SELECT image_path FROM menu_items WHERE id = ?', [itemId]);
    if (!rows.length) {
      setFlash(req, 'error', 'ไม่พบเมนูย่อ');
      return res.redirect('/admin/menu-items');
    }

    const imagePath = rows[0].image_path;
    await pool.query('DELETE FROM menu_items WHERE id = ?', [itemId]);
    await removeFileIfExists(imagePath);

    setFlash(req, 'success', 'ลบเมนูย่อเรียบร้อยแล้ว');
    return res.redirect('/admin/menu-items');
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการลบเมนูย่อ:', error);
    setFlash(req, 'error', 'ไม่สามารถลบเมนูย่อได้');
    return res.redirect('/admin/menu-items');
  }
});

// News Categories Routes
app.get('/admin/news-categories', requireRole('admin'), async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT 
         nc.id, 
         nc.name, 
         nc.description, 
         nc.color, 
         nc.is_active, 
         nc.display_order, 
         nc.created_at, 
         nc.updated_at,
         COUNT(n.id) as news_count
       FROM news_categories nc
       LEFT JOIN news n ON nc.id = n.category_id AND n.is_published = 1
       GROUP BY nc.id
       ORDER BY nc.display_order ASC, nc.created_at DESC`
    );
    
    const categories = rows.map((row) => ({
      id: row.id,
      name: row.name,
      description: row.description,
      color: row.color,
      isActive: Boolean(row.is_active),
      displayOrder: row.display_order,
      newsCount: Number.parseInt(row.news_count, 10) || 0,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    }));

    return res.render('admin-news-categories', {
      title: 'จัดการหมวดหมู่ข่าวประชาสัมพันธ์',
      categories
    });
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการโหลดหมวดหมู่ข่าว:', error);
    setFlash(req, 'error', 'ไม่สามารถโหลดรายการหมวดหมู่ข่าวได้');
    return res.redirect('/admin/dashboard');
  }
});

app.get('/admin/news-categories/new', requireRole('admin'), (req, res) => {
  return res.render('admin-news-category-form', {
    title: 'เพิ่มหมวดหมู่ข่าวประชาสัมพันธ์',
    mode: 'create',
    category: null
  });
});

app.post('/admin/news-categories', requireRole('admin'), async (req, res) => {
  const { name, description, color, display_order: displayOrderRaw, is_active: isActiveRaw } = req.body;
  const trimmedName = name?.trim();
  const trimmedDescription = description?.trim() || null;
  const trimmedColor = color?.trim() || 'primary';
  const displayOrder = Number.isNaN(Number.parseInt(displayOrderRaw, 10)) ? 0 : Number.parseInt(displayOrderRaw, 10);
  const isActive = isActiveRaw ? 1 : 0;

  if (!trimmedName) {
    setFlash(req, 'error', 'กรุณาระบุชื่อหมวดหมู่ข่าว');
    return res.redirect('/admin/news-categories/new');
  }

  try {
    await pool.query(
      `INSERT INTO news_categories (name, description, color, is_active, display_order)
       VALUES (?, ?, ?, ?, ?)`,
      [trimmedName, trimmedDescription, trimmedColor, isActive, displayOrder]
    );
    setFlash(req, 'success', 'เพิ่มหมวดหมู่ข่าวใหม่เรียบร้อยแล้ว');
    return res.redirect('/admin/news-categories');
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการบันทึกหมวดหมู่ข่าว:', error);
    setFlash(req, 'error', 'ไม่สามารถบันทึกหมวดหมู่ข่าวได้');
    return res.redirect('/admin/news-categories/new');
  }
});

app.get('/admin/news-categories/:id/edit', requireRole('admin'), async (req, res) => {
  const categoryId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(categoryId)) {
    setFlash(req, 'error', 'หมวดหมู่ข่าวไม่ถูกต้อง');
    return res.redirect('/admin/news-categories');
  }

  try {
    const [rows] = await pool.query(
      'SELECT id, name, description, color, is_active, display_order FROM news_categories WHERE id = ?',
      [categoryId]
    );

    if (!rows.length) {
      setFlash(req, 'error', 'ไม่พบหมวดหมู่ข่าว');
      return res.redirect('/admin/news-categories');
    }

    const category = rows[0];
    return res.render('admin-news-category-form', {
      title: 'แก้ไขหมวดหมู่ข่าวประชาสัมพันธ์',
      mode: 'edit',
      category: {
        id: category.id,
        name: category.name,
        description: category.description,
        color: category.color,
        isActive: Boolean(category.is_active),
        displayOrder: category.display_order
      }
    });
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการโหลดหมวดหมู่ข่าวเพื่อแก้ไข:', error);
    setFlash(req, 'error', 'ไม่สามารถโหลดหมวดหมู่ข่าวได้');
    return res.redirect('/admin/news-categories');
  }
});

app.post('/admin/news-categories/:id', requireRole('admin'), async (req, res) => {
  const categoryId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(categoryId)) {
    setFlash(req, 'error', 'หมวดหมู่ข่าวไม่ถูกต้อง');
    return res.redirect('/admin/news-categories');
  }

  const { name, description, color, display_order: displayOrderRaw, is_active: isActiveRaw } = req.body;
  const trimmedName = name?.trim();
  const trimmedDescription = description?.trim() || null;
  const trimmedColor = color?.trim() || 'primary';
  const displayOrder = Number.isNaN(Number.parseInt(displayOrderRaw, 10)) ? 0 : Number.parseInt(displayOrderRaw, 10);
  const isActive = isActiveRaw ? 1 : 0;

  if (!trimmedName) {
    setFlash(req, 'error', 'กรุณาระบุชื่อหมวดหมู่ข่าว');
    return res.redirect(`/admin/news-categories/${categoryId}/edit`);
  }

  try {
    const [rows] = await pool.query('SELECT id FROM news_categories WHERE id = ?', [categoryId]);
    if (!rows.length) {
      setFlash(req, 'error', 'ไม่พบหมวดหมู่ข่าว');
      return res.redirect('/admin/news-categories');
    }

    await pool.query(
      `UPDATE news_categories 
       SET name = ?, description = ?, color = ?, is_active = ?, display_order = ?
       WHERE id = ?`,
      [trimmedName, trimmedDescription, trimmedColor, isActive, displayOrder, categoryId]
    );

    setFlash(req, 'success', 'อัปเดตหมวดหมู่ข่าวเรียบร้อยแล้ว');
    return res.redirect('/admin/news-categories');
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการอัปเดตหมวดหมู่ข่าว:', error);
    setFlash(req, 'error', 'ไม่สามารถอัปเดตหมวดหมู่ข่าวได้');
    return res.redirect(`/admin/news-categories/${categoryId}/edit`);
  }
});

app.post('/admin/news-categories/:id/delete', requireRole('admin'), async (req, res) => {
  const categoryId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(categoryId)) {
    setFlash(req, 'error', 'หมวดหมู่ข่าวไม่ถูกต้อง');
    return res.redirect('/admin/news-categories');
  }

  try {
    const [rows] = await pool.query('SELECT id FROM news_categories WHERE id = ?', [categoryId]);
    if (!rows.length) {
      setFlash(req, 'error', 'ไม่พบหมวดหมู่ข่าว');
      return res.redirect('/admin/news-categories');
    }

    await pool.query('DELETE FROM news_categories WHERE id = ?', [categoryId]);
    setFlash(req, 'success', 'ลบหมวดหมู่ข่าวเรียบร้อยแล้ว');
    return res.redirect('/admin/news-categories');
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการลบหมวดหมู่ข่าว:', error);
    setFlash(req, 'error', 'ไม่สามารถลบหมวดหมู่ข่าวได้');
    return res.redirect('/admin/news-categories');
  }
});

// News by Category Page
app.get('/news/category/:slug', async (req, res) => {
  const { slug } = req.params;
  
  try {
    // ดึงข้อมูลหมวดหมู่
    const [categoryRows] = await pool.query(
      'SELECT id, name, description, color FROM news_categories WHERE id = ? AND is_active = 1',
      [slug]
    );
    
    if (!categoryRows.length) {
      return res.status(404).render('404', { title: 'ไม่พบหมวดหมู่ข่าว' });
    }
    
    const category = categoryRows[0];
    
    // ดึงข้อมูลข่าวในหมวดหมู่นี้
    const [newsRows] = await pool.query(
      `SELECT
         n.id,
         n.title,
         n.slug,
         n.content,
         n.image_path,
         n.image_caption,
         n.created_at,
         u.name AS author_name,
         u.profile_image AS author_image,
         u.position AS author_position,
         u.affiliation AS author_affiliation,
         (SELECT COUNT(*) FROM news_files nf WHERE nf.news_id = n.id) AS attachment_count
       FROM news n
       LEFT JOIN users u ON n.author_id = u.id
       WHERE n.is_published = 1 AND n.category_id = ?
       ORDER BY n.created_at DESC`,
      [category.id]
    );
    
    const news = newsRows.map((row) => ({
      id: row.id,
      title: row.title,
      slug: row.slug,
      preview: (() => {
        const text = stripHtml(row.content);
        if (text.length <= 220) return text;
        return `${text.slice(0, 220).trimEnd()}…`;
      })(),
      imagePath: row.image_path,
      imageCaption: row.image_caption,
      author: {
        name: row.author_name || 'ทีมผู้ดูแลระบบ',
        image: row.author_image,
        position: row.author_position,
        affiliation: row.author_affiliation
      },
      attachmentCount: Number.parseInt(row.attachment_count, 10) || 0,
      createdAt: row.created_at
    }));

    return res.render('news-category', {
      title: `ข่าว${category.name}`,
      category: {
        id: category.id,
        name: category.name,
        description: category.description,
        color: category.color
      },
      news
    });
  } catch (error) {
    console.error('เกิดข้อผิดพลาดในการแสดงข่าวตามหมวดหมู่:', error);
    setFlash(req, 'error', 'ไม่สามารถเปิดข่าวตามหมวดหมู่ได้');
    return res.redirect('/');
  }
});

app.use((req, res) => {
  res.status(404).render('404', { title: 'ไม่พบหน้านี้' });
});

async function initializeDatabase() {
  try {
    const ensureTableColumn = async (tableName, columnName, definition) => {
      const [columns] = await pool.query(`SHOW COLUMNS FROM ${tableName} LIKE ?`, [columnName]);
      if (!columns.length) {
        await pool.query(`ALTER TABLE ${tableName} ADD COLUMN ${definition}`);
      }
    };
    const ensureSiteSetting = async (key, value) => {
      await pool.query(
        `INSERT INTO site_settings (setting_key, setting_value)
         VALUES (?, ?)
         ON DUPLICATE KEY UPDATE setting_key = setting_key`,
        [key, value]
      );
    };

    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        phone VARCHAR(20) DEFAULT NULL,
        \`position\` VARCHAR(255) DEFAULT NULL,
        affiliation VARCHAR(255) DEFAULT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role ENUM('admin', 'staff') NOT NULL DEFAULT 'staff',
        is_approved TINYINT(1) NOT NULL DEFAULT 0,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    await ensureTableColumn('users', 'phone', 'phone VARCHAR(20) DEFAULT NULL AFTER email');
    await ensureTableColumn(
      'users',
      'position',
      '`position` VARCHAR(255) DEFAULT NULL AFTER phone'
    );
    await ensureTableColumn(
      'users',
      'affiliation',
      'affiliation VARCHAR(255) DEFAULT NULL AFTER `position`'
    );
    await ensureTableColumn(
      'users',
      'profile_image',
      'profile_image VARCHAR(255) DEFAULT NULL AFTER affiliation'
    );
    await ensureTableColumn(
      'users',
      'is_approved',
      'is_approved TINYINT(1) NOT NULL DEFAULT 0 AFTER role'
    );

    await pool.query(`
      CREATE TABLE IF NOT EXISTS news (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        slug VARCHAR(255) NOT NULL UNIQUE,
        author_id INT DEFAULT NULL,
        content TEXT NOT NULL,
        image_path VARCHAR(255) DEFAULT NULL,
        image_caption VARCHAR(255) DEFAULT NULL,
        is_published TINYINT(1) NOT NULL DEFAULT 1,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    await ensureTableColumn(
      'news',
      'author_id',
      'author_id INT DEFAULT NULL AFTER slug'
    );
    await ensureTableColumn(
      'news',
      'image_caption',
      'image_caption VARCHAR(255) DEFAULT NULL AFTER image_path'
    );
    await ensureTableColumn(
      'news',
      'category_id',
      'category_id INT DEFAULT NULL AFTER author_id'
    );

    await pool.query(`
      CREATE TABLE IF NOT EXISTS slider_images (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        caption VARCHAR(500) DEFAULT NULL,
        link VARCHAR(500) DEFAULT NULL,
        image_path VARCHAR(255) NOT NULL,
        is_active TINYINT(1) NOT NULL DEFAULT 1,
        display_order INT NOT NULL DEFAULT 0,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS news_files (
        id INT AUTO_INCREMENT PRIMARY KEY,
        news_id INT NOT NULL,
        file_path VARCHAR(255) NOT NULL,
        original_name VARCHAR(255) NOT NULL,
        file_size BIGINT UNSIGNED NOT NULL DEFAULT 0,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_news_files_news
          FOREIGN KEY (news_id) REFERENCES news(id)
          ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS site_settings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        setting_key VARCHAR(100) NOT NULL UNIQUE,
        setting_value TEXT DEFAULT NULL,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    await ensureSiteSetting('site_name', defaultSiteSettings.siteName);
    await ensureSiteSetting('site_status', defaultSiteSettings.siteStatus);
    await ensureSiteSetting('site_logo', '');

    await pool.query(`
      CREATE TABLE IF NOT EXISTS news_likes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        news_id INT NOT NULL,
        user_id INT NOT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_news_user (news_id, user_id),
        CONSTRAINT fk_news_likes_news FOREIGN KEY (news_id) REFERENCES news(id) ON DELETE CASCADE,
        CONSTRAINT fk_news_likes_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS menu_categories (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT DEFAULT NULL,
        icon VARCHAR(100) DEFAULT NULL,
        color VARCHAR(20) DEFAULT 'primary',
        is_active TINYINT(1) NOT NULL DEFAULT 1,
        display_order INT NOT NULL DEFAULT 0,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS menu_items (
        id INT AUTO_INCREMENT PRIMARY KEY,
        category_id INT NOT NULL,
        title VARCHAR(255) NOT NULL,
        description TEXT DEFAULT NULL,
        link VARCHAR(500) DEFAULT NULL,
        image_path VARCHAR(255) DEFAULT NULL,
        is_active TINYINT(1) NOT NULL DEFAULT 1,
        display_order INT NOT NULL DEFAULT 0,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        CONSTRAINT fk_menu_items_category FOREIGN KEY (category_id) REFERENCES menu_categories(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS news_categories (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT DEFAULT NULL,
        color VARCHAR(20) DEFAULT 'primary',
        is_active TINYINT(1) NOT NULL DEFAULT 1,
        display_order INT NOT NULL DEFAULT 0,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    const [rows] = await pool.query('SELECT COUNT(*) AS count FROM users WHERE role = ?', ['admin']);
    const adminCount = rows[0]?.count || 0;
    if (adminCount === 0) {
      const defaultPassword = process.env.DEFAULT_ADMIN_PASSWORD || 'admin123';
      const passwordHash = await bcrypt.hash(defaultPassword, 10);
      await pool.query(
        'INSERT INTO users (name, email, password_hash, role, is_approved) VALUES (?, ?, ?, ?, ?)',
        ['ผู้ดูแลระบบหลัก', 'admin@example.com', passwordHash, 'admin', 1]
      );
      console.log(`สร้างผู้ดูแลระบบเริ่มต้นแล้ว: admin@example.com / ${defaultPassword}`);
    }
    invalidateSiteSettingsCache();
  } catch (error) {
    console.error('ไม่สามารถเตรียมฐานข้อมูลได้:', error);
    throw error;
  }
}

initializeDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`เซิร์ฟเวอร์กำลังรันที่ http://localhost:${PORT}`);
    });
  })
  .catch((error) => {
    console.error('ไม่สามารถเริ่มต้นระบบได้:', error);
    process.exit(1);
  });
