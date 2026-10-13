<?php
/*
 * NAISC 2026 Portal + MySQL backend.
 * Konfigurasi database dapat diubah pada variabel DB_* di bawah atau melalui environment.
 * Login admin membaca tabel admin_users dan memverifikasi password_hash dengan password_verify().
 * Optional first-admin provisioning: set NAISC_ADMIN_USER dan NAISC_ADMIN_PASSWORD.
 */
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_set_cookie_params(['httponly' => true, 'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'), 'samesite' => 'Lax']);
    session_start();
}

$DB_HOST = getenv('DB_HOST') ?: '127.0.0.1';
$DB_NAME = getenv('DB_NAME') ?: 'naisc_2026';
$DB_USER = getenv('DB_USER') ?: 'root';
$DB_PASS = getenv('DB_PASS') !== false ? getenv('DB_PASS') : '';

function jsonResponse(array $payload, int $status = 200): never {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
function db(): PDO {
    global $DB_HOST, $DB_NAME, $DB_USER, $DB_PASS;
    static $pdo = null;
    if ($pdo instanceof PDO) return $pdo;
    $pdo = new PDO("mysql:host={$DB_HOST};dbname={$DB_NAME};charset=utf8mb4", $DB_USER, $DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    return $pdo;
}
function requestData(): array {
    $raw = file_get_contents('php://input');
    $data = json_decode($raw ?: '[]', true);
    return is_array($data) ? $data : [];
}
function requireAdmin(): void {
    if (empty($_SESSION['naisc_admin_id'])) jsonResponse(['success' => false, 'message' => 'Silakan login sebagai administrator terlebih dahulu.'], 401);
}
function registrationRows(PDO $pdo): array {
    $stmt = $pdo->query("SELECT r.*, DATE_FORMAT(r.registered_at, '%Y-%m-%d %H:%i') AS display_date,
        GROUP_CONCAT(rm.member_name ORDER BY rm.member_order SEPARATOR ', ') AS extra_members
        FROM registrations r LEFT JOIN registration_members rm ON rm.registration_id = r.id
        GROUP BY r.id ORDER BY r.registered_at DESC");
    $out = [];
    foreach ($stmt->fetchAll() as $r) {
        $type = $r['registration_type'];
        $members = [];
        if ($type !== 'Workshop') {
            $members[] = 'Ketua: ' . $r['participant_or_team_name'];
            if (!empty($r['extra_members'])) $members[] = 'Anggota: ' . $r['extra_members'];
        }
        $out[] = [
            'id' => $r['registration_code'], 'registration_code' => $r['registration_code'],
            'date' => $r['display_date'], 'name' => $r['participant_or_team_name'],
            'institution' => $r['institution'], 'type' => $type, 'email' => $r['email'],
            'whatsapp' => $r['whatsapp'], 'members' => $type === 'Workshop' ? '-' : implode(', ', $members),
            'link' => $r['work_link'] ?: '', 'proof' => $r['payment_proof_url'] ?: '',
            'payment_status' => $r['payment_status'], 'status' => $r['verification_status'],
            'registration_fee' => (float)$r['registration_fee'], 'registered_at' => $r['registered_at']
        ];
    }
    return $out;
}

$action = $_GET['action'] ?? '';
if ($action !== '') {
    try {
        $pdo = db();
        // Optional first administrator creation. Supply a strong password through environment variables.
        $adminUser = getenv('NAISC_ADMIN_USER');
        $adminPass = getenv('NAISC_ADMIN_PASSWORD');
        if ($adminUser && $adminPass) {
            $check = $pdo->prepare('SELECT id FROM admin_users WHERE username = ? LIMIT 1');
            $check->execute([$adminUser]);
            if (!$check->fetch()) {
                $create = $pdo->prepare('INSERT INTO admin_users (username, password_hash, full_name) VALUES (?, ?, ?)');
                $create->execute([$adminUser, password_hash($adminPass, PASSWORD_DEFAULT), 'Administrator NAISC']);
            }
        }
        $input = requestData();
        switch ($action) {
            case 'health':
                // Endpoint pemeriksaan koneksi dan kolom yang dibutuhkan backend.
                $adminCount = (int)$pdo->query('SELECT COUNT(*) FROM admin_users')->fetchColumn();
                $required = [
                    'registrations' => ['registration_code','registration_type','participant_or_team_name','institution','email','whatsapp','work_link','registration_fee','payment_proof_url','payment_status','verification_status','registered_at'],
                    'registration_members' => ['registration_id','member_name','member_order'],
                    'admin_users' => ['username','password_hash','full_name','is_active','last_login_at']
                ];
                $schemaCheck = [];
                foreach ($required as $table => $columns) {
                    $found = $pdo->query('SHOW COLUMNS FROM `' . $table . '`')->fetchAll(PDO::FETCH_COLUMN);
                    $schemaCheck[$table] = ['exists' => true, 'missing_columns' => array_values(array_diff($columns, $found))];
                }
                jsonResponse([
                    'success' => true,
                    'database_connected' => true,
                    'database' => $DB_NAME,
                    'admin_table_available' => true,
                    'admin_account_count' => $adminCount,
                    'schema_check' => $schemaCheck,
                    'message' => $adminCount > 0 ? 'Database terhubung dan akun admin tersedia.' : 'Database terhubung, tetapi tabel admin_users belum memiliki akun.'
                ]);

            case 'register':
                if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonResponse(['success'=>false,'message'=>'Metode tidak diizinkan.'], 405);
                $type = trim((string)($input['type'] ?? ''));
                $name = trim((string)($input['name'] ?? ''));
                $institution = trim((string)($input['institution'] ?? ''));
                $email = trim((string)($input['email'] ?? ''));
                $whatsapp = trim((string)($input['whatsapp'] ?? ''));
                if (!in_array($type, ['Workshop','Lomba Mobile','Lomba Website'], true)) jsonResponse(['success'=>false,'message'=>'Jenis pendaftaran tidak valid.'], 422);
                if ($name === '' || $institution === '' || $whatsapp === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) jsonResponse(['success'=>false,'message'=>'Nama, institusi, email valid, dan WhatsApp wajib diisi.'], 422);
                $isWorkshop = $type === 'Workshop';
                $link = $isWorkshop ? null : trim((string)($input['link'] ?? ''));
                if ($link !== null && $link !== '' && !filter_var($link, FILTER_VALIDATE_URL)) jsonResponse(['success'=>false,'message'=>'Format tautan karya tidak valid.'], 422);
                $proof = $isWorkshop ? null : trim((string)($input['proof'] ?? ''));
                $fee = $isWorkshop ? 0 : 50000;
                $paymentStatus = $isWorkshop ? 'Tidak Diperlukan' : ($proof !== '' ? 'Menunggu Verifikasi' : 'Belum Dibayar');
                $verifyStatus = $isWorkshop ? 'Terverifikasi' : 'Pending';
                $code = '';
                for ($attempt=0; $attempt<5; $attempt++) {
                    $code = 'NAISC-2026-' . strtoupper(bin2hex(random_bytes(4)));
                    $check = $pdo->prepare('SELECT id FROM registrations WHERE registration_code = ?');
                    $check->execute([$code]);
                    if (!$check->fetch()) break;
                }
                $pdo->beginTransaction();
                $stmt = $pdo->prepare('INSERT INTO registrations (registration_code, registration_type, participant_or_team_name, institution, email, whatsapp, work_link, registration_fee, payment_proof_url, payment_status, verification_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
                $stmt->execute([$code, $type, $name, $institution, $email, $whatsapp, ($link === '' ? null : $link), $fee, ($proof === '' ? null : $proof), $paymentStatus, $verifyStatus]);
                $registrationId = (int)$pdo->lastInsertId();
                if (!$isWorkshop) {
                    $memberStmt = $pdo->prepare('INSERT INTO registration_members (registration_id, member_name, member_order) VALUES (?, ?, ?)');
                    foreach ([2 => trim((string)($input['member1'] ?? '')), 3 => trim((string)($input['member2'] ?? ''))] as $order => $member) {
                        if ($member !== '') $memberStmt->execute([$registrationId, $member, $order]);
                    }
                }
                $pdo->commit();
                jsonResponse(['success'=>true,'registration_code'=>$code]);

            case 'login':
                if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonResponse(['success'=>false,'message'=>'Metode tidak diizinkan.'], 405);
                $username = trim((string)($input['username'] ?? ''));
                $password = (string)($input['password'] ?? '');
                $stmt = $pdo->prepare('SELECT id, username, password_hash, full_name FROM admin_users WHERE username = ? AND is_active = 1 LIMIT 1');
                $stmt->execute([$username]); $admin = $stmt->fetch();
                if (!$admin) {
                    $activeCount = (int)$pdo->query('SELECT COUNT(*) FROM admin_users WHERE is_active = 1')->fetchColumn();
                    if ($activeCount === 0) jsonResponse(['success'=>false,'message'=>'Belum ada akun admin aktif di database. Tambahkan akun pada tabel admin_users terlebih dahulu.'], 401);
                    jsonResponse(['success'=>false,'message'=>'Username tidak ditemukan atau akun admin tidak aktif. Periksa tabel admin_users.'], 401);
                }
                if (!password_verify($password, $admin['password_hash'])) jsonResponse(['success'=>false,'message'=>'Password admin salah. Pastikan password sesuai dengan hash yang tersimpan di database.'], 401);
                session_regenerate_id(true);
                $_SESSION['naisc_admin_id'] = (int)$admin['id'];
                $_SESSION['naisc_admin_name'] = $admin['full_name'];
                $pdo->prepare('UPDATE admin_users SET last_login_at = NOW() WHERE id = ?')->execute([$admin['id']]);
                jsonResponse(['success'=>true,'name'=>$admin['full_name']]);

            case 'session':
                jsonResponse(['success'=>true,'authenticated'=>!empty($_SESSION['naisc_admin_id'])]);

            case 'logout':
                $_SESSION = [];
                if (ini_get('session.use_cookies')) {
                    $params = session_get_cookie_params();
                    setcookie(session_name(), '', time()-42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
                }
                session_destroy();
                jsonResponse(['success'=>true]);

            case 'list':
                requireAdmin();
                jsonResponse(['success'=>true,'data'=>registrationRows($pdo)]);

            case 'toggle_status':
                requireAdmin();
                $code = trim((string)($input['registration_code'] ?? ''));
                $stmt = $pdo->prepare("UPDATE registrations SET verification_status = CASE WHEN verification_status = 'Terverifikasi' THEN 'Pending' ELSE 'Terverifikasi' END WHERE registration_code = ?");
                $stmt->execute([$code]);
                if (!$stmt->rowCount()) jsonResponse(['success'=>false,'message'=>'Data pendaftaran tidak ditemukan atau status tidak berubah.'], 404);
                jsonResponse(['success'=>true]);

            case 'delete':
                requireAdmin();
                $code = trim((string)($input['registration_code'] ?? ''));
                $stmt = $pdo->prepare('DELETE FROM registrations WHERE registration_code = ?');
                $stmt->execute([$code]);
                if (!$stmt->rowCount()) jsonResponse(['success'=>false,'message'=>'Data pendaftaran tidak ditemukan.'], 404);
                jsonResponse(['success'=>true]);

            default:
                jsonResponse(['success'=>false,'message'=>'Aksi tidak dikenal.'], 404);
        }
    } catch (Throwable $e) {
        if (isset($pdo) && $pdo instanceof PDO && $pdo->inTransaction()) $pdo->rollBack();
        error_log('NAISC portal error: ' . $e->getMessage());
        $message = 'Terjadi kesalahan pada server/database. Periksa struktur tabel dan log PHP.';
        if (isset($_GET['debug']) && $_GET['debug'] === '1') {
            $message .= ' Detail teknis: ' . $e->getMessage();
        }
        jsonResponse(['success'=>false,'message'=>$message], 500);
    }
}
?>
<!DOCTYPE html>
<html lang="id" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NAISC 2026 - National AI Summit & Competition</title>
    <!-- Tailwind CSS CDN -->
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        navy: {
                            900: '#060b14',
                            800: '#0b1d3a',
                            700: '#132a52',
                            600: '#1b3b72',
                        },
                        gold: {
                            300: '#fde047',
                            400: '#facc15',
                            500: '#d4af37',
                            600: '#b89628',
                        },
                        cyan: {
                            400: '#22d3ee',
                            500: '#06b6d4',
                            600: '#0891b2',
                        }
                    },
                    fontFamily: {
                        sans: ['Plus Jakarta Sans', 'Inter', 'sans-serif'],
                    }
                }
            }
        }
    </script>
    <!-- Google Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <!-- FontAwesome Icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
    <style>
        body {
            font-family: 'Plus Jakarta Sans', sans-serif;
            background-color: #060b14;
            color: #f1f5f9;
            overflow-x: hidden;
        }

        /* Glassmorphism Classes */
        .glass-panel {
            background: rgba(11, 29, 58, 0.75);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid rgba(212, 175, 55, 0.2);
        }

        .glass-panel-hover:hover {
            border-color: rgba(212, 175, 55, 0.5);
            box-shadow: 0 10px 30px -10px rgba(0, 242, 254, 0.25);
        }

        .glass-modal {
            background: rgba(6, 11, 20, 0.92);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid rgba(212, 175, 55, 0.3);
        }

        /* Text Gradients */
        .text-gradient-gold {
            background: linear-gradient(135deg, #fff2ac 0%, #d4af37 50%, #aa7c11 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .text-gradient-cyan {
            background: linear-gradient(135deg, #a5f3fc 0%, #00f2fe 50%, #0284c7 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        /* Glowing Orbs */
        .glow-orb {
            position: absolute;
            border-radius: 50%;
            filter: blur(90px);
            z-index: 0;
            pointer-events: none;
        }

        /* Custom Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
        }
        ::-webkit-scrollbar-track {
            background: #060b14;
        }
        ::-webkit-scrollbar-thumb {
            background: #1b3b72;
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: #d4af37;
        }

        /* Balinese Geometric Accent Pattern */
        .bali-pattern {
            background-image: radial-gradient(rgba(212, 175, 55, 0.12) 1px, transparent 1px), radial-gradient(rgba(0, 242, 254, 0.08) 1px, #060b14 1px);
            background-size: 30px 30px;
            background-position: 0 0, 15px 15px;
        }

        /* Print styles for export */
        @media print {
            body * {
                visibility: hidden;
            }
            #printableAdminArea, #printableAdminArea * {
                visibility: visible;
            }
            #printableAdminArea {
                position: absolute;
                left: 0;
                top: 0;
                width: 100%;
                color: #000;
                background: #fff;
                padding: 20px;
            }
            .no-print {
                display: none !important;
            }
        }
    </style>
</head>
<body class="bali-pattern min-h-screen text-slate-100 flex flex-col justify-between">

    <!-- Background Ambient Light -->
    <div class="glow-orb w-96 h-96 bg-blue-600/20 top-10 left-10"></div>
    <div class="glow-orb w-[30rem] h-[30rem] bg-amber-500/10 top-1/3 right-10"></div>
    <div class="glow-orb w-96 h-96 bg-cyan-500/15 bottom-20 left-1/4"></div>

    <!-- HEADER NAVBAR -->
    <header class="sticky top-0 z-40 backdrop-blur-xl bg-navy-900/80 border-b border-amber-500/20 transition-all duration-300">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-20 flex items-center justify-between">
            
            <!-- Brand Logos & Title -->
            <a href="#" class="flex items-center gap-3 group">
                <div class="flex items-center gap-2">
                    <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-amber-400 via-amber-500 to-navy-900 p-[2px] shadow-lg shadow-amber-500/20">
                        <div class="w-full h-full bg-navy-900 rounded-[10px] flex items-center justify-center font-bold text-amber-400 text-lg">
                            <i class="fa-solid fa-brain"></i>
                        </div>
                    </div>
                </div>
                <div>
                    <div class="flex items-center gap-2">
                        <span class="font-extrabold text-xl tracking-tight text-gradient-gold">NAISC</span>
                        <span class="text-xs bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 px-2 py-0.5 rounded-full font-semibold">2026</span>
                    </div>
                    <p class="text-[10px] text-slate-400 font-medium">UMS &bull; BIM University Bali</p>
                </div>
            </a>

            <!-- Desktop Navigation -->
            <nav class="hidden lg:flex items-center gap-7 text-sm font-medium text-slate-300">
                <a href="#beranda" class="hover:text-amber-400 transition-colors">Beranda</a>
                <a href="#tentang" class="hover:text-amber-400 transition-colors">Tentang</a>
                <a href="#workshop" class="hover:text-amber-400 transition-colors">Workshop</a>
                <a href="#lomba" class="hover:text-amber-400 transition-colors">Lomba AI</a>
                <a href="#kriteria" class="hover:text-amber-400 transition-colors">Kriteria</a>
                <a href="#jadwal" class="hover:text-amber-400 transition-colors">Jadwal</a>
                <a href="#pendaftaran" class="hover:text-amber-400 transition-colors">Pendaftaran</a>
                <a href="#faq" class="hover:text-amber-400 transition-colors">FAQ</a>
            </nav>

            <!-- Right Actions: Admin Button & Mobile Menu Toggle -->
            <div class="flex items-center gap-3">
                <!-- Dedicated Admin Button -->
                <div id="adminNavContainer">
                    <button id="openAdminBtn" onclick="handleAdminBtnClick()" class="flex items-center gap-2 px-4 py-2 rounded-xl text-xs sm:text-sm font-semibold transition-all duration-300 bg-gradient-to-r from-amber-500/20 via-amber-500/10 to-transparent border border-amber-500/50 text-amber-300 hover:bg-amber-500 hover:text-navy-900 shadow-lg shadow-amber-500/10 hover:shadow-amber-500/30">
                        <i class="fa-solid fa-lock text-amber-400 group-hover:text-navy-900"></i>
                        <span id="adminBtnLabel">Akses Admin</span>
                    </button>
                </div>

                <!-- CTA Quick Register -->
                <a href="#pendaftaran" class="hidden sm:inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs sm:text-sm font-bold bg-gradient-to-r from-cyan-500 to-blue-600 text-white hover:from-cyan-400 hover:to-blue-500 shadow-md shadow-cyan-500/20 hover:shadow-cyan-500/40 transition-all">
                    <span>Daftar Sekarang</span>
                    <i class="fa-solid fa-arrow-right text-xs"></i>
                </a>

                <!-- Mobile Menu Button -->
                <button id="mobileMenuBtn" onclick="toggleMobileMenu()" class="lg:hidden p-2 rounded-lg bg-slate-800/80 text-slate-300 hover:text-amber-400">
                    <i class="fa-solid fa-bars text-lg"></i>
                </button>
            </div>

        </div>

        <!-- Mobile Drawer -->
        <div id="mobileMenu" class="hidden lg:hidden border-b border-slate-800 bg-navy-900/95 px-6 py-4 space-y-3">
            <a href="#beranda" onclick="toggleMobileMenu()" class="block py-2 text-slate-300 hover:text-amber-400">Beranda</a>
            <a href="#tentang" onclick="toggleMobileMenu()" class="block py-2 text-slate-300 hover:text-amber-400">Tentang NAISC</a>
            <a href="#workshop" onclick="toggleMobileMenu()" class="block py-2 text-slate-300 hover:text-amber-400">Workshop AI (Gratis)</a>
            <a href="#lomba" onclick="toggleMobileMenu()" class="block py-2 text-slate-300 hover:text-amber-400">Kompetisi Lomba</a>
            <a href="#kriteria" onclick="toggleMobileMenu()" class="block py-2 text-slate-300 hover:text-amber-400">Kriteria Penilaian</a>
            <a href="#jadwal" onclick="toggleMobileMenu()" class="block py-2 text-slate-300 hover:text-amber-400">Jadwal & Timeline</a>
            <a href="#pendaftaran" onclick="toggleMobileMenu()" class="block py-2 text-amber-400 font-bold">Form Pendaftaran</a>
            <a href="#faq" onclick="toggleMobileMenu()" class="block py-2 text-slate-300 hover:text-amber-400">FAQ & Kontak</a>
        </div>
    </header>

    <main class="flex-grow">
        <!-- HERO SECTION -->
        <section id="beranda" class="relative pt-12 pb-20 lg:pt-20 lg:pb-32 overflow-hidden">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
                <div class="text-center max-w-4xl mx-auto space-y-6">
                    
                    <!-- Host Collaboration Badges -->
                    <div class="inline-flex items-center gap-3 px-4 py-2 rounded-full glass-panel border border-amber-500/30 text-xs sm:text-sm font-medium text-amber-300 animate-pulse">
                        <span class="flex items-center gap-1.5"><i class="fa-solid fa-university"></i> UMS Surakarta</span>
                        <span class="text-slate-500">&bull;</span>
                        <span class="flex items-center gap-1.5"><i class="fa-solid fa-synagogue"></i> BIM University Bali</span>
                    </div>

                    <!-- Main Title -->
                    <h1 class="text-4xl sm:text-6xl lg:text-7xl font-extrabold tracking-tight leading-tight">
                        National AI Summit & <br>
                        <span class="text-gradient-gold">Competition 2026</span>
                    </h1>

                    <p class="text-slate-300 text-base sm:text-xl max-w-2xl mx-auto font-light leading-relaxed">
                        Ajang puncak kreativitas, inovasi, dan kolaborasi talenta muda Indonesia dalam memprediksi serta membentuk masa depan kecerdasan buatan.
                    </p>

                    <!-- Event Location & Date Badge -->
                    <div class="flex flex-wrap justify-center items-center gap-4 text-xs sm:text-sm text-slate-300">
                        <div class="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800/60 border border-slate-700">
                            <i class="fa-solid fa-calendar-days text-amber-400"></i>
                            <span>Rabu, 25 November 2026</span>
                        </div>
                        <div class="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800/60 border border-slate-700">
                            <i class="fa-solid fa-location-dot text-cyan-400"></i>
                            <span>BIM University, Denpasar - Bali</span>
                        </div>
                    </div>

                    <!-- Countdown Timer Container -->
                    <div class="pt-6 pb-2">
                        <p class="text-xs uppercase tracking-widest text-slate-400 font-semibold mb-3">Menuju Puncak Acara (WITA):</p>
                        <div class="grid grid-cols-4 gap-2 sm:gap-4 max-w-lg mx-auto">
                            <div class="glass-panel p-3 sm:p-4 rounded-2xl text-center">
                                <span id="cd-days" class="block text-2xl sm:text-4xl font-extrabold text-amber-400">00</span>
                                <span class="text-[10px] sm:text-xs text-slate-400 uppercase font-medium">Hari</span>
                            </div>
                            <div class="glass-panel p-3 sm:p-4 rounded-2xl text-center">
                                <span id="cd-hours" class="block text-2xl sm:text-4xl font-extrabold text-slate-100">00</span>
                                <span class="text-[10px] sm:text-xs text-slate-400 uppercase font-medium">Jam</span>
                            </div>
                            <div class="glass-panel p-3 sm:p-4 rounded-2xl text-center">
                                <span id="cd-minutes" class="block text-2xl sm:text-4xl font-extrabold text-cyan-400">00</span>
                                <span class="text-[10px] sm:text-xs text-slate-400 uppercase font-medium">Menit</span>
                            </div>
                            <div class="glass-panel p-3 sm:p-4 rounded-2xl text-center">
                                <span id="cd-seconds" class="block text-2xl sm:text-4xl font-extrabold text-slate-100">00</span>
                                <span class="text-[10px] sm:text-xs text-slate-400 uppercase font-medium">Detik</span>
                            </div>
                        </div>
                    </div>

                    <!-- Hero Call to Actions -->
                    <div class="flex flex-col sm:flex-row justify-center items-center gap-4 pt-4">
                        <a href="#pendaftaran" class="w-full sm:w-auto px-8 py-4 rounded-2xl bg-gradient-to-r from-amber-500 via-amber-400 to-yellow-500 text-navy-900 font-extrabold text-base shadow-xl shadow-amber-500/25 hover:shadow-amber-500/40 hover:scale-105 transition-all">
                            <i class="fa-solid fa-paper-plane mr-2"></i> Daftar NAISC 2026
                        </a>
                        <a href="#workshop" class="w-full sm:w-auto px-8 py-4 rounded-2xl glass-panel border border-cyan-500/40 text-cyan-300 font-bold text-base hover:bg-cyan-500/10 transition-all">
                            <i class="fa-solid fa-chalkboard-user mr-2"></i> Daftar Workshop
                        </a>
                    </div>

                </div>
            </div>
        </section>

        <!-- ABOUT SECTION -->
        <section id="tentang" class="py-16 relative bg-navy-900/60 border-y border-slate-800">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
                    
                    <div class="space-y-6">
                        <div class="inline-flex items-center gap-2 text-cyan-400 text-xs font-bold uppercase tracking-wider">
                            <i class="fa-solid fa-circle-info"></i> Latar Belakang & Tujuan
                        </div>
                        <h2 class="text-3xl sm:text-4xl font-bold leading-tight">
                            Mendorong Akselerasi <span class="text-gradient-gold">Sains Data & AI</span> Berbasis Riset & Terapan
                        </h2>
                        <p class="text-slate-300 leading-relaxed text-sm sm:text-base">
                            NAISC 2026 diselenggarakan melalui sinergi strategis antara **Universitas Muhammadiyah Surakarta (UMS)** dan **BIM University Bali**. Program ini dirancang untuk menjembatani talenta muda tingkat Sekolah Menengah/Sederajat dan Perguruan Tinggi dengan standar industri Artificial Intelligence terkini.
                        </p>
                        
                        <!-- Highlights List -->
                        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
                            <div class="glass-panel p-4 rounded-xl flex items-start gap-3">
                                <div class="p-2 bg-amber-500/20 text-amber-400 rounded-lg"><i class="fa-solid fa-lightbulb text-lg"></i></div>
                                <div>
                                    <h4 class="font-bold text-sm text-slate-100">Inovasi Praktis</h4>
                                    <p class="text-xs text-slate-400">Solusi nyata untuk permasalahan riil di masyarakat.</p>
                                </div>
                            </div>
                            <div class="glass-panel p-4 rounded-xl flex items-start gap-3">
                                <div class="p-2 bg-cyan-500/20 text-cyan-400 rounded-lg"><i class="fa-solid fa-handshake text-lg"></i></div>
                                <div>
                                    <h4 class="font-bold text-sm text-slate-100">Kemitraan DUDI</h4>
                                    <p class="text-xs text-slate-400">Sesuai standar Dunia Usaha & Dunia Industri.</p>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Info Graphic Card -->
                    <div class="glass-panel p-8 rounded-3xl relative overflow-hidden border border-amber-500/30">
                        <div class="absolute -right-10 -bottom-10 w-40 h-40 bg-amber-500/10 rounded-full blur-2xl"></div>
                        <h3 class="text-xl font-bold mb-4 text-amber-400 flex items-center gap-2">
                            <i class="fa-solid fa-award"></i> Kenapa Harus Bergabung?
                        </h3>
                        <ul class="space-y-4 text-sm text-slate-300">
                            <li class="flex items-start gap-3">
                                <i class="fa-solid fa-circle-check text-cyan-400 mt-1"></i>
                                <span><strong>Sertifikat Tingkat Nasional</strong> </span>
                            </li>
                            <li class="flex items-start gap-3">
                                <i class="fa-solid fa-circle-check text-cyan-400 mt-1"></i>
                                <span><strong>Mentoring Eksklusif:</strong> Bimbingan langsung dari Pakar AI & Developer Senior.</span>
                            </li>
                            <li class="flex items-start gap-3">
                                <i class="fa-solid fa-circle-check text-cyan-400 mt-1"></i>
                                <span><strong>Total Hadiah Jutaan Rupiah:</strong> Trophy, Piagam Penghargaan, & Beasiswa Pendidikan.</span>
                            </li>
                            <li class="flex items-start gap-3">
                                <i class="fa-solid fa-circle-check text-cyan-400 mt-1"></i>
                                <span><strong>Networking Luas:</strong> Kesempatan berjejaring dengan akademisi, praktisi, dan talenta AI nasional.</span>
                            </li>
                        </ul>
                    </div>

                </div>
            </div>
        </section>

        <!-- WORKSHOP SECTION -->
        <section id="workshop" class="py-20 relative">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="text-center max-w-3xl mx-auto mb-12">
                    <span class="px-3 py-1 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 text-xs font-extrabold uppercase">
                        Sesi Pembekalan Gratis
                    </span>
                    <h2 class="text-3xl sm:text-5xl font-extrabold mt-3 text-slate-100">
                        Workshop AI <span class="text-gradient-cyan">Mobile Apps</span>
                    </h2>
                    <p class="text-slate-400 text-sm sm:text-base mt-3">
                        Pelatihan hands-on tanpa biaya pendaftaran untuk membekali peserta dengan keterampilan integrasi API AI (LLM & Vision) ke dalam aplikasi mobile modern.
                    </p>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div class="glass-panel p-6 rounded-2xl glass-panel-hover transition-all">
                        <div class="w-12 h-12 bg-cyan-500/20 text-cyan-400 rounded-xl flex items-center justify-center text-xl font-bold mb-4">
                            <i class="fa-solid fa-code"></i>
                        </div>
                        <h3 class="text-lg font-bold text-slate-100 mb-2">Integrasi LLM & Prompt Engineering</h3>
                        <p class="text-xs text-slate-400 leading-relaxed">
                            Mempelajari penggunaan API kecerdasan buatan, pembuatan sistem prompt, serta penanganan respon terstruktur untuk mobile app.
                        </p>
                    </div>

                    <div class="glass-panel p-6 rounded-2xl glass-panel-hover transition-all">
                        <div class="w-12 h-12 bg-amber-500/20 text-amber-400 rounded-xl flex items-center justify-center text-xl font-bold mb-4">
                            <i class="fa-solid fa-mobile-screen-button"></i>
                        </div>
                        <h3 class="text-lg font-bold text-slate-100 mb-2">UI/UX AI-Driven Mobile Apps</h3>
                        <p class="text-xs text-slate-400 leading-relaxed">
                            Merancang antarmuka aplikasi yang intuitif, responsif, dan ramah pengguna dengan komponen interaktif berbasis AI.
                        </p>
                    </div>

                    <div class="glass-panel p-6 rounded-2xl glass-panel-hover transition-all">
                        <div class="w-12 h-12 bg-purple-500/20 text-purple-400 rounded-xl flex items-center justify-center text-xl font-bold mb-4">
                            <i class="fa-solid fa-rocket"></i>
                        </div>
                        <h3 class="text-lg font-bold text-slate-100 mb-2">Deployment & Prototyping</h3>
                        <p class="text-xs text-slate-400 leading-relaxed">
                            Teknik menyusun prototype aplikasi siap guna dan cara mempresentasikannya di depan dewan juri & praktisi DUDI.
                        </p>
                    </div>
                </div>

                <div class="mt-8 text-center">
                    <a href="#pendaftaran" onclick="selectRegistrationType('workshop')" class="inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-navy-900 font-bold text-sm transition-all shadow-lg shadow-cyan-500/20">
                        <i class="fa-solid fa-user-plus"></i> Daftar Workshop (Gratis)
                    </a>
                </div>
            </div>
        </section>

        <!-- COMPETITION SECTION -->
        <section id="lomba" class="py-20 bg-navy-900/80 border-y border-slate-800">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="text-center max-w-3xl mx-auto mb-14">
                    <span class="px-3 py-1 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/40 text-xs font-extrabold uppercase">
                        Kompetisi NAISC
                    </span>
                    <h2 class="text-3xl sm:text-5xl font-extrabold mt-3 text-slate-100">
                        Kategori <span class="text-gradient-gold">Lomba AI</span>
                    </h2>
                    <p class="text-slate-400 text-sm sm:text-base mt-3">
                        Biaya pendaftaran yang sangat terjangkau: <strong class="text-amber-400 font-bold">Rp 50.000 / Tim</strong> (Maksimal 3 Orang / Tim).
                    </p>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                    
                    <!-- Category 1 -->
                    <div class="glass-panel p-8 rounded-3xl border-2 border-amber-500/30 relative overflow-hidden flex flex-col justify-between">
                        <div class="absolute top-0 right-0 bg-amber-500 text-navy-900 text-[10px] font-black uppercase px-4 py-1 rounded-bl-xl">
                            Kategori 1
                        </div>
                        <div>
                            <div class="w-14 h-14 bg-amber-500/20 rounded-2xl flex items-center justify-center text-amber-400 text-2xl mb-6">
                                <i class="fa-solid fa-mobile-retro"></i>
                            </div>
                            <h3 class="text-2xl font-bold text-slate-100 mb-3">AI Mobile Apps Development</h3>
                            <p class="text-slate-300 text-sm mb-6 leading-relaxed">
                                Pengembangan aplikasi perangkat bergerak (Android / iOS / Cross-platform) yang memanfaatkan fitur kecerdasan buatan secara inovatif untuk membantu produktivitas, pendidikan, kesehatan, atau industri.
                            </p>
                            <div class="space-y-2 text-xs text-slate-400 mb-6">
                                <div class="flex items-center gap-2"><i class="fa-solid fa-check text-amber-400"></i> Integrasi API / On-Device AI Model</div>
                                <div class="flex items-center gap-2"><i class="fa-solid fa-check text-amber-400"></i> Pengumpulan Demo Video & APK / Source Code</div>
                                <div class="flex items-center gap-2"><i class="fa-solid fa-check text-amber-400"></i> Presentasi Finalis @ BIM University Bali</div>
                            </div>
                        </div>
                        <button onclick="selectRegistrationType('lomba_mobile')" class="w-full py-3 rounded-xl bg-amber-500 hover:bg-amber-400 text-navy-900 font-extrabold text-sm transition-all shadow-md">
                            Daftar Lomba Mobile Apps (Rp 50rb)
                        </button>
                    </div>

                    <!-- Category 2 -->
                    <div class="glass-panel p-8 rounded-3xl border-2 border-cyan-500/30 relative overflow-hidden flex flex-col justify-between">
                        <div class="absolute top-0 right-0 bg-cyan-500 text-navy-900 text-[10px] font-black uppercase px-4 py-1 rounded-bl-xl">
                            Kategori 2
                        </div>
                        <div>
                            <div class="w-14 h-14 bg-cyan-500/20 rounded-2xl flex items-center justify-center text-cyan-400 text-2xl mb-6">
                                <i class="fa-solid fa-globe"></i>
                            </div>
                            <h3 class="text-2xl font-bold text-slate-100 mb-3">AI Web Applications</h3>
                            <p class="text-slate-300 text-sm mb-6 leading-relaxed">
                                Pembangunan platform atau aplikasi berbasis web cerdas yang mengintegrasikan model machine learning, pemrosesan bahasa alami (NLP), computer vision, atau agen AI interaktif.
                            </p>
                            <div class="space-y-2 text-xs text-slate-400 mb-6">
                                <div class="flex items-center gap-2"><i class="fa-solid fa-check text-cyan-400"></i> Fullstack Web Framework / Cloud Deployment</div>
                                <div class="flex items-center gap-2"><i class="fa-solid fa-check text-cyan-400"></i> Tanggap Solusi Masalah Sosial & Bisnis</div>
                                <div class="flex items-center gap-2"><i class="fa-solid fa-check text-cyan-400"></i> Presentasi Finalis @ BIM University Bali</div>
                            </div>
                        </div>
                        <button onclick="selectRegistrationType('lomba_web')" class="w-full py-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-navy-900 font-extrabold text-sm transition-all shadow-md">
                            Daftar Lomba Website AI (Rp 50rb)
                        </button>
                    </div>

                </div>
            </div>
        </section>

        <!-- KRITERIA SECTION -->
        <section id="kriteria" class="py-20 relative">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="text-center max-w-3xl mx-auto mb-14">
                    <span class="text-xs font-bold text-amber-400 uppercase tracking-widest">Penilaian Objektif & Transparan</span>
                    <h2 class="text-3xl sm:text-4xl font-extrabold text-slate-100 mt-2">Kriteria Penilaian Karya</h2>
                </div>

                <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
                    <div class="glass-panel p-6 rounded-2xl text-center border-t-4 border-amber-500">
                        <div class="text-3xl font-extrabold text-amber-400 mb-2">30%</div>
                        <h4 class="font-bold text-slate-100 text-base mb-1">Inovasi & Originalitas</h4>
                        <p class="text-xs text-slate-400">Kebaruan ide, keunikan pendekatan AI, dan solusi kreatif atas masalah.</p>
                    </div>

                    <div class="glass-panel p-6 rounded-2xl text-center border-t-4 border-cyan-400">
                        <div class="text-3xl font-extrabold text-cyan-400 mb-2">30%</div>
                        <h4 class="font-bold text-slate-100 text-base mb-1">Kualitas Teknis</h4>
                        <p class="text-xs text-slate-400">Arsitektur AI, performa sistem, kebersihan kode, serta skalabilitas.</p>
                    </div>

                    <div class="glass-panel p-6 rounded-2xl text-center border-t-4 border-purple-400">
                        <div class="text-3xl font-extrabold text-purple-400 mb-2">20%</div>
                        <h4 class="font-bold text-slate-100 text-base mb-1">Desain & UI/UX</h4>
                        <p class="text-xs text-slate-400">Kenyamanan pengguna, estetika antarmuka, dan aksesibilitas aplikasi.</p>
                    </div>

                    <div class="glass-panel p-6 rounded-2xl text-center border-t-4 border-emerald-400">
                        <div class="text-3xl font-extrabold text-emerald-400 mb-2">20%</div>
                        <h4 class="font-bold text-slate-100 text-base mb-1">Presentasi & Dampak</h4>
                        <p class="text-xs text-slate-400">Kemampuan penyampaian karya, pitchdeck, serta dampak potensial.</p>
                    </div>
                </div>
            </div>
        </section>

        <!-- TIMELINE SECTION -->
        <section id="jadwal" class="py-20 bg-navy-900/60 border-t border-slate-800">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="text-center max-w-3xl mx-auto mb-14">
                    <span class="text-xs font-bold text-cyan-400 uppercase tracking-widest">Jadwal Kegiatan</span>
                    <h2 class="text-3xl sm:text-4xl font-extrabold text-slate-100 mt-2">Timeline NAISC 2026</h2>
                </div>

                <div class="relative max-w-4xl mx-auto">
                    <!-- Vertical Line -->
                    <div class="absolute left-1/2 transform -translate-x-1/2 h-full w-1 bg-slate-800 hidden md:block"></div>

                    <div class="space-y-8">
                        <!-- Item 1 -->
                        <div class="flex flex-col md:flex-row items-center justify-between gap-6">
                            <div class="w-full md:w-5/12 text-right md:text-right order-2 md:order-1">
                                <div class="glass-panel p-5 rounded-2xl">
                                    <span class="text-xs font-bold text-amber-400">11 Oktober - 21 November 2026</span>
                                    <h4 class="font-bold text-base text-slate-100 mt-1">Pendaftaran Peserta Workshop</h4>
                                </div>
                            </div>
                            <div class="w-10 h-10 rounded-full bg-amber-500 text-navy-900 flex items-center justify-center font-bold z-10 order-1 md:order-2 shadow-lg shadow-amber-500/30">
                                1
                            </div>
                            <div class="w-full md:w-5/12 order-3 hidden md:block"></div>
                        </div>

                        <!-- Item 2 -->
                        <div class="flex flex-col md:flex-row items-center justify-between gap-6">
                            <div class="w-full md:w-5/12 order-3 md:order-1 hidden md:block"></div>
                            <div class="w-10 h-10 rounded-full bg-cyan-500 text-navy-900 flex items-center justify-center font-bold z-10 order-1 md:order-2 shadow-lg shadow-cyan-500/30">
                                2
                            </div>
                            <div class="w-full md:w-5/12 text-left order-2 md:order-3">
                                <div class="glass-panel p-5 rounded-2xl">
                                    <span class="text-xs font-bold text-cyan-400">1 Oktober - 14 November 2026</span>
                                    <h4 class="font-bold text-base text-slate-100 mt-1">Pendaftaran & Pengumpulan Berkas Lomba</h4>
                                </div>
                            </div>
                        </div>

                        <!-- Item 3 -->
                        <div class="flex flex-col md:flex-row items-center justify-between gap-6">
                            <div class="w-full md:w-5/12 text-right md:text-right order-2 md:order-1">
                                <div class="glass-panel p-5 rounded-2xl">
                                    <span class="text-xs font-bold text-purple-400">10 - 19 November 2026</span>
                                    <h4 class="font-bold text-base text-slate-100 mt-1">Penjurian Awal Peserta Lomba</h4>
                                </div>
                            </div>
                            <div class="w-10 h-10 rounded-full bg-purple-500 text-navy-900 flex items-center justify-center font-bold z-10 order-1 md:order-2">
                                3
                            </div>
                            <div class="w-full md:w-5/12 order-3 hidden md:block"></div>
                        </div>

                        <!-- Item 4 -->
                        <div class="flex flex-col md:flex-row items-center justify-between gap-6">
                            <div class="w-full md:w-5/12 order-3 md:order-1 hidden md:block"></div>
                            <div class="w-10 h-10 rounded-full bg-amber-400 text-navy-900 flex items-center justify-center font-bold z-10 order-1 md:order-2 shadow-lg shadow-amber-400/50">
                                4
                            </div>
                            <div class="w-full md:w-5/12 text-left order-2 md:order-3">
                                <div class="glass-panel p-5 rounded-2xl border border-amber-500/50 bg-amber-500/10">
                                    <span class="text-xs font-bold text-amber-300">21 November 2026</span>
                                    <h4 class="font-bold text-base text-amber-400 mt-1">Notifikasi Hasil Penjurian</h4>
                                </div>
                            </div>
                        </div>

                        <!-- Item 4 -->
                        <div class="flex flex-col md:flex-row items-center justify-between gap-6">
                            <div class="w-full md:w-5/12 text-right md:text-right order-2 md:order-1">
                                <div class="glass-panel p-5 rounded-2xl">
                                    <span class="text-xs font-bold text-purple-400">25 November 2026 (08:00 WITA)</span>
                                    <h4 class="font-bold text-base text-slate-100 mt-1">Pelaksanaan Workshop AI</h4>
                                    <h4 class="font-bold text-base text-slate-100 mt-1">Babak Final Lomba</h4>
                                    <h4 class="font-bold text-base text-slate-100 mt-1">Awarding dan Pengumuman Pemenang</h4>
                                </div>
                            </div>
                            <div class="w-10 h-10 rounded-full bg-purple-500 text-navy-900 flex items-center justify-center font-bold z-10 order-1 md:order-2">
                                4
                            </div>
                            <div class="w-full md:w-5/12 order-3 hidden md:block"></div>
                        </div>

                    </div>
                </div>
            </div>
        </section>

        <!-- REGISTRATION FORM SECTION -->
        <section id="pendaftaran" class="py-20 relative">
            <div class="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="glass-panel p-6 sm:p-10 rounded-3xl border border-amber-500/40 shadow-2xl relative">
                    
                    <div class="text-center mb-8">
                        <span class="text-xs font-bold text-amber-400 uppercase tracking-widest">Formulir Pendaftaran</span>
                        <h2 class="text-2xl sm:text-4xl font-extrabold text-slate-100 mt-1">Registrasi NAISC 2026</h2>
                        <p class="text-xs sm:text-sm text-slate-400 mt-2">Isi data lengkap Anda di bawah ini. Data pendaftaran akan otomatis tersimpan dalam sistem terverifikasi.</p>
                    </div>

                    <form id="registrationForm" onsubmit="handleRegistrationSubmit(event)" class="space-y-6">
                        
                        <!-- Pilihan formulir: Workshop atau Lomba -->
                        <div>
                            <label class="block text-xs font-bold uppercase text-slate-300 mb-2">Jenis Pendaftaran <span class="text-amber-400">*</span></label>
                            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                <label class="cursor-pointer">
                                    <input type="radio" name="regType" value="Workshop" class="peer hidden" checked onchange="toggleFormFields()">
                                    <div class="p-4 rounded-xl border border-slate-700 bg-slate-900/60 peer-checked:border-amber-400 peer-checked:bg-amber-500/10 text-center transition-all">
                                        <div class="font-bold text-sm text-slate-200"><i class="fa-solid fa-chalkboard-user mr-1"></i> Pendaftaran Workshop AI</div>
                                        <div class="text-[11px] text-slate-400 mt-1">Perorangan · Gratis · Tanpa tautan karya</div>
                                    </div>
                                </label>
                                <label class="cursor-pointer">
                                    <input type="radio" name="regType" value="Lomba" class="peer hidden" onchange="toggleFormFields()">
                                    <div class="p-4 rounded-xl border border-slate-700 bg-slate-900/60 peer-checked:border-amber-400 peer-checked:bg-amber-500/10 text-center transition-all">
                                        <div class="font-bold text-sm text-slate-200"><i class="fa-solid fa-trophy mr-1"></i> Pendaftaran Lomba AI</div>
                                        <div class="text-[11px] text-slate-400 mt-1">Tim maksimal 3 orang · Rp 50.000 / tim</div>
                                    </div>
                                </label>
                            </div>
                            <div id="competitionCategorySection" class="hidden mt-4">
                                <label for="competitionCategory" class="block text-xs font-semibold text-slate-300 mb-1">Kategori Lomba <span class="text-amber-400">*</span></label>
                                <select id="competitionCategory" class="w-full px-4 py-3 rounded-xl bg-slate-900/80 border border-slate-700 text-slate-100 text-sm focus:outline-none focus:border-amber-400" onchange="updateCompetitionLabel()">
                                    <option value="Lomba Mobile">Lomba Mobile Apps</option>
                                    <option value="Lomba Website">Lomba Website AI</option>
                                </select>
                            </div>
                        </div>

                        <!-- Full Name / Team Name -->
                        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <div>
                                <label id="labelParticipantName" class="block text-xs font-semibold text-slate-300 mb-1">Nama Lengkap Peserta / Ketua Tim <span class="text-amber-400">*</span></label>
                                <input type="text" id="regName" required placeholder="Contoh: I Gede Yoga Pratama" class="w-full px-4 py-3 rounded-xl bg-slate-900/80 border border-slate-700 text-slate-100 text-sm focus:outline-none focus:border-amber-400">
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-300 mb-1">Sekolah / Perguruan Tinggi <span class="text-amber-400">*</span></label>
                                <input type="text" id="regInstitution" required placeholder="Contoh: SMA Negeri 1 Denpasar / UMS" class="w-full px-4 py-3 rounded-xl bg-slate-900/80 border border-slate-700 text-slate-100 text-sm focus:outline-none focus:border-amber-400">
                            </div>
                        </div>

                        <!-- Contact Details -->
                        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <div>
                                <label class="block text-xs font-semibold text-slate-300 mb-1">Email Aktif <span class="text-amber-400">*</span></label>
                                <input type="email" id="regEmail" required placeholder="email@domain.com" class="w-full px-4 py-3 rounded-xl bg-slate-900/80 border border-slate-700 text-slate-100 text-sm focus:outline-none focus:border-amber-400">
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-300 mb-1">Nomor WhatsApp Aktif <span class="text-amber-400">*</span></label>
                                <input type="tel" id="regWhatsapp" required placeholder="08123456789" class="w-full px-4 py-3 rounded-xl bg-slate-900/80 border border-slate-700 text-slate-100 text-sm focus:outline-none focus:border-amber-400">
                            </div>
                        </div>

                        <!-- Additional Team Members (Visible for Competition) -->
                        <div id="teamSection" class="hidden space-y-3 p-4 rounded-xl bg-slate-900/50 border border-slate-800">
                            <label class="block text-xs font-bold text-amber-300">Anggota Tim Tambahan (Opsional - Maks 2 Orang)</label>
                            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                <input type="text" id="regMember1" placeholder="Nama Anggota 2" class="px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200">
                                <input type="text" id="regMember2" placeholder="Nama Anggota 3" class="px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200">
                            </div>
                        </div>

                        <!-- Link karya hanya untuk peserta lomba; tidak ditampilkan pada formulir Workshop -->
                        <div id="competitionLinkSection" class="hidden">
                            <label id="competitionLinkLabel" class="block text-xs font-semibold text-slate-300 mb-1">Link Karya (Google Drive / GitHub / Figma)</label>
                            <input type="url" id="regLink" placeholder="https://..." class="w-full px-4 py-3 rounded-xl bg-slate-900/80 border border-slate-700 text-slate-100 text-sm focus:outline-none focus:border-amber-400">
                            <p class="text-[10px] text-slate-500 mt-1">Masukkan tautan karya atau repositori jika sudah tersedia.</p>
                        </div>

                        <!-- Payment Information (Visible for Competition) -->
                        <div id="paymentNotice" class="hidden p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-xs text-slate-300 space-y-2">
                            <p class="font-bold text-amber-400"><i class="fa-solid fa-credit-card mr-1"></i> Informasi Pembayaran Registrasi Lomba (Rp 50.000):</p>
                            <p>Silakan transfer ke <strong>Bank Jago: 104513242878 a.n. Muhammad Syahriandi Adhantoro </strong></p>
                            <p>Panitia NAISC 2026</p>
                            <div>
                                <label class="block text-[11px] font-semibold text-slate-300 mb-1">Link Google Drive Bukti Transfer (Nomor Referensi / Catatan Transaksi):</label>
                                <input type="text" id="regPaymentProof" placeholder="https://drive.google.com/" class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-100">
                            </div>
                        </div>

                        <!-- Submit Button -->
                        <button type="submit" class="w-full py-4 rounded-xl bg-gradient-to-r from-amber-500 via-amber-400 to-yellow-500 text-navy-900 font-extrabold text-base hover:shadow-lg hover:shadow-amber-500/30 transition-all flex items-center justify-center gap-2">
                            <i class="fa-solid fa-paper-plane"></i> Kirim Pendaftaran
                        </button>
                    </form>

                </div>
            </div>
        </section>

        <section id="faq" class="py-20 bg-navy-900/80 border-t border-slate-800">
                    <div class="flex flex-col sm:flex-row justify-center items-center gap-4 pt-4">
                        <a href="https://drive.google.com/file/d/1ED2Kw3qqL56JMtW1zzjHpuLe2L_lQTw9/view?usp=sharing" class="w-full sm:w-auto px-8 py-4 rounded-2xl bg-gradient-to-r from-amber-500 via-amber-400 to-yellow-500 text-navy-900 font-extrabold text-base shadow-xl shadow-amber-500/25 hover:shadow-amber-500/40 hover:scale-105 transition-all">
                            <i class="fa-solid fa-paper-plane mr-2"></i> Buku Panduan NAISC 2026
                        </a>
                        <a href="https://drive.google.com/file/d/1kOsEreej_xALtNHX46dLqBVnw1P8olhc/view?usp=sharing" class="w-full sm:w-auto px-8 py-4 rounded-2xl glass-panel border border-cyan-500/40 text-cyan-300 font-bold text-base hover:bg-cyan-500/10 transition-all">
                            <i class="fa-solid fa-chalkboard-user mr-2"></i> Leaflet NAISC 2026
                        </a>
                    </div>
        </section>
        <!-- FAQ & CONTACT SECTION -->
        <section id="faq" class="py-20 bg-navy-900/80 border-t border-slate-800">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-12">
                    <!-- FAQ Accordion -->
                    <div class="space-y-6">
                        <div>
                            <span class="text-xs font-bold text-cyan-400 uppercase tracking-widest">Pusat Bantuan</span>
                            <h2 class="text-2xl sm:text-3xl font-extrabold text-slate-100 mt-1">Pertanyaan Sering Diajukan (FAQ)</h2>
                        </div>

                        <div class="space-y-3">
                            <!-- Q1 -->
                            <details class="glass-panel rounded-xl p-4 group">
                                <summary class="font-bold text-sm text-slate-200 cursor-pointer flex justify-between items-center">
                                    Apakah siswa SMA/SMK boleh mendaftar?
                                    <i class="fa-solid fa-chevron-down text-xs text-slate-400 group-open:rotate-180 transition-transform"></i>
                                </summary>
                                <p class="text-xs text-slate-400 mt-3 leading-relaxed">
                                    Ya, NAISC 2026 terbuka untuk siswa SMA/SMK/MA sederajat serta mahasiswa aktif jenjang D3/D4/S1 dari seluruh Indonesia.
                                </p>
                            </details>

                            <!-- Q2 -->
                            <details class="glass-panel rounded-xl p-4 group">
                                <summary class="font-bold text-sm text-slate-200 cursor-pointer flex justify-between items-center">
                                    Apakah pendaftaran Workshop benar-benar gratis?
                                    <i class="fa-solid fa-chevron-down text-xs text-slate-400 group-open:rotate-180 transition-transform"></i>
                                </summary>
                                <p class="text-xs text-slate-400 mt-3 leading-relaxed">
                                    Benar, Sesi Workshop AI Mobile Apps 100% Bebas Biaya (Gratis) dan seluruh peserta mendapatkan e-sertifikat kehadiran.
                                </p>
                            </details>

                            <!-- Q3 -->
                            <details class="glass-panel rounded-xl p-4 group">
                                <summary class="font-bold text-sm text-slate-200 cursor-pointer flex justify-between items-center">
                                    Bagaimana jika saya belum memiliki tim untuk Lomba?
                                    <i class="fa-solid fa-chevron-down text-xs text-slate-400 group-open:rotate-180 transition-transform"></i>
                                </summary>
                                <p class="text-xs text-slate-400 mt-3 leading-relaxed">
                                    Anda dapat mendaftar secara individu (1 orang) atau membentuk tim maksimal berisi 3 orang peserta dari instansi yang sama maupun berbeda.
                                </p>
                            </details>
                        </div>
                    </div>

                    <!-- Contact & Secretariat Info -->
                    <div class="glass-panel p-8 rounded-3xl border border-cyan-500/30 flex flex-col justify-between">
                        <div>
                            <span class="text-xs font-bold text-amber-400 uppercase tracking-widest">Sekretariat Panitia</span>
                            <h3 class="text-2xl font-bold text-slate-100 mt-1 mb-4">Sekretariat NAISC 2026</h3>
                            
                            <div class="space-y-4 text-xs text-slate-300">
                                <div class="flex items-start gap-3">
                                    <i class="fa-solid fa-location-dot text-amber-400 text-base mt-0.5"></i>
                                    <div>
                                        <strong>BIM University Campus:</strong><br>
                                        Jl. Bypass Ngurah Rai No. 88, Sanur, Denpasar, Bali - 80228
                                    </div>
                                </div>

                                <div class="flex items-start gap-3">
                                    <i class="fa-solid fa-building-columns text-cyan-400 text-base mt-0.5"></i>
                                    <div>
                                        <strong>Universitas Muhammadiyah Surakarta:</strong><br>
                                        Jl. A. Yani, Pabelan, Kartasura, Surakarta, Jawa Tengah
                                    </div>
                                </div>

                                <div class="flex items-center gap-3">
                                    <i class="fa-solid fa-envelope text-amber-400 text-base"></i>
                                    <span>naisc2026@bim.ac.id / naisc@ums.ac.id</span>
                                </div>
                            </div>
                        </div>

                        <!-- Contact Persons -->
                        <div class="mt-8 pt-6 border-t border-slate-800">
                            <h4 class="font-bold text-xs text-slate-300 uppercase mb-3">Contact Person (WhatsApp):</h4>
                            <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
                                <a href="https://wa.me/6281234567890" target="_blank" class="p-3 rounded-xl bg-slate-900 border border-slate-700 hover:border-amber-400 text-center transition-all">
                                    <div class="font-bold text-xs text-amber-400">Laizza</div>
                                    <div class="text-[10px] text-slate-400">0812-3456-7890</div>
                                </a>
                                <a href="https://wa.me/6281987654321" target="_blank" class="p-3 rounded-xl bg-slate-900 border border-slate-700 hover:border-amber-400 text-center transition-all">
                                    <div class="font-bold text-xs text-amber-400">Hasbi</div>
                                    <div class="text-[10px] text-slate-400">0819-8765-4321</div>
                                </a>
                                <a href="https://wa.me/6281122334455" target="_blank" class="p-3 rounded-xl bg-slate-900 border border-slate-700 hover:border-amber-400 text-center transition-all">
                                    <div class="font-bold text-xs text-amber-400">Vedo</div>
                                    <div class="text-[10px] text-slate-400">0811-2233-4455</div>
                                </a>
                            </div>
                        </div>

                    </div>
                </div>

            </div>
        </section>
    </main>

    <!-- FOOTER -->
    <footer class="bg-navy-900 border-t border-slate-800 py-8 text-center text-xs text-slate-500">
        <div class="max-w-7xl mx-auto px-4">
            <p>&copy; 2026 National AI Summit & Competition (NAISC). Organized by UMS & BIM University Bali.</p>
        </div>
    </footer>

    <!-- ==================== ADMIN LOGIN MODAL ==================== -->
    <div id="adminLoginModal" class="fixed inset-0 z-50 hidden flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
        <div class="glass-modal w-full max-w-md p-6 sm:p-8 rounded-3xl shadow-2xl relative border border-amber-500/40">
            
            <!-- Close Button -->
            <button onclick="closeAdminLoginModal()" class="absolute top-4 right-4 text-slate-400 hover:text-white p-2">
                <i class="fa-solid fa-xmark text-lg"></i>
            </button>

            <div class="text-center mb-6">
                <div class="w-14 h-14 bg-amber-500/20 text-amber-400 rounded-2xl flex items-center justify-center text-2xl mx-auto mb-3 border border-amber-500/40">
                    <i class="fa-solid fa-user-shield"></i>
                </div>
                <h3 class="text-2xl font-bold text-slate-100">Login Administrator</h3>
                <p class="text-xs text-slate-400 mt-1">Masuk untuk mengelola data pendaftar NAISC 2026.</p>
            </div>

            <form onsubmit="handleAdminLogin(event)" class="space-y-4">
                <div>
                    <label class="block text-xs font-semibold text-slate-300 mb-1">Username</label>
                    <input type="text" id="adminUsername" required placeholder="admin" class="w-full px-4 py-3 rounded-xl bg-slate-900 border border-slate-700 text-slate-100 text-sm focus:outline-none focus:border-amber-400">
                </div>

                <div>
                    <label class="block text-xs font-semibold text-slate-300 mb-1">Password</label>
                    <input type="password" id="adminPassword" required placeholder="••••••••" class="w-full px-4 py-3 rounded-xl bg-slate-900 border border-slate-700 text-slate-100 text-sm focus:outline-none focus:border-amber-400">
                </div>

                <!-- Alert Message Container -->
                <div id="loginErrorMsg" class="hidden p-3 rounded-xl bg-rose-500/20 border border-rose-500/40 text-rose-300 text-xs text-center font-medium"></div>

                <button type="submit" class="w-full py-3.5 rounded-xl bg-amber-500 hover:bg-amber-400 text-navy-900 font-extrabold text-sm transition-all shadow-lg shadow-amber-500/20">
                    Masuk Mode Admin
                </button>
            </form>

        </div>
    </div>

    <!-- ==================== ADMIN DASHBOARD MODAL ==================== -->
    <div id="adminDashboardModal" class="fixed inset-0 z-50 hidden flex items-center justify-center p-2 sm:p-6 bg-black/85 backdrop-blur-lg overflow-y-auto">
        <div class="glass-modal w-full max-w-6xl max-h-[92vh] rounded-3xl shadow-2xl flex flex-col border border-amber-500/40 my-auto">
            
            <!-- Dashboard Header -->
            <div class="p-5 sm:p-6 border-b border-slate-800 flex flex-wrap items-center justify-between gap-4 bg-navy-900/90 rounded-t-3xl">
                <div class="flex items-center gap-3">
                    <div class="p-2.5 bg-amber-500/20 text-amber-400 rounded-xl border border-amber-500/30">
                        <i class="fa-solid fa-chart-line text-xl"></i>
                    </div>
                    <div>
                        <div class="flex items-center gap-2">
                            <h3 class="text-xl font-bold text-slate-100">Panel Admin & Eksport Data</h3>
                            <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">Sistem Aktif</span>
                        </div>
                        <p class="text-xs text-slate-400">Kelola verifikasi peserta dan unduh laporan pendaftaran NAISC 2026.</p>
                    </div>
                </div>

                <!-- Actions: Export buttons & Logout -->
                <div class="flex flex-wrap items-center gap-2">
                    <button onclick="exportDataCSV()" class="px-3 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold flex items-center gap-1.5 transition-all shadow-md">
                        <i class="fa-solid fa-file-excel"></i> Ekspor CSV
                    </button>
                    <button onclick="exportDataJSON()" class="px-3 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold flex items-center gap-1.5 transition-all shadow-md">
                        <i class="fa-solid fa-code"></i> Ekspor JSON
                    </button>
                    <button onclick="printAdminReport()" class="px-3 py-2 rounded-xl bg-slate-700 hover:bg-slate-600 text-slate-200 text-xs font-bold flex items-center gap-1.5 transition-all shadow-md">
                        <i class="fa-solid fa-print"></i> Cetak / PDF
                    </button>
                    <button onclick="handleAdminLogout()" class="px-3 py-2 rounded-xl bg-rose-500/20 border border-rose-500/40 text-rose-300 hover:bg-rose-500 hover:text-white text-xs font-bold transition-all">
                        <i class="fa-solid fa-right-from-bracket"></i> Keluar
                    </button>
                    <button onclick="closeAdminDashboardModal()" class="p-2 text-slate-400 hover:text-white">
                        <i class="fa-solid fa-xmark text-lg"></i>
                    </button>
                </div>
            </div>

            <!-- Dashboard Content Container -->
            <div id="printableAdminArea" class="p-5 sm:p-6 overflow-y-auto space-y-6 flex-grow">
                
                <!-- SUMMARY STAT CARDS -->
                <div class="grid grid-cols-2 lg:grid-cols-5 gap-3 sm:gap-4 no-print">
                    <div class="glass-panel p-4 rounded-2xl border-l-4 border-amber-400">
                        <p class="text-[11px] font-semibold text-slate-400 uppercase">Total Pendaftar</p>
                        <h4 id="statTotal" class="text-2xl font-extrabold text-amber-400 mt-1">0</h4>
                    </div>
                    <div class="glass-panel p-4 rounded-2xl border-l-4 border-cyan-400">
                        <p class="text-[11px] font-semibold text-slate-400 uppercase">Peserta Workshop</p>
                        <h4 id="statWorkshop" class="text-2xl font-extrabold text-cyan-400 mt-1">0</h4>
                    </div>
                    <div class="glass-panel p-4 rounded-2xl border-l-4 border-amber-500">
                        <p class="text-[11px] font-semibold text-slate-400 uppercase">Tim Lomba Mobile</p>
                        <h4 id="statMobile" class="text-2xl font-extrabold text-slate-100 mt-1">0</h4>
                    </div>
                    <div class="glass-panel p-4 rounded-2xl border-l-4 border-blue-400">
                        <p class="text-[11px] font-semibold text-slate-400 uppercase">Tim Lomba Web</p>
                        <h4 id="statWeb" class="text-2xl font-extrabold text-slate-100 mt-1">0</h4>
                    </div>
                    <div class="glass-panel p-4 rounded-2xl border-l-4 border-emerald-400 col-span-2 lg:col-span-1">
                        <p class="text-[11px] font-semibold text-slate-400 uppercase">Total Pendapatan</p>
                        <h4 id="statRevenue" class="text-xl font-extrabold text-emerald-400 mt-1">Rp 0</h4>
                    </div>
                </div>

                <!-- FILTER & SEARCH BAR -->
                <div class="flex flex-col sm:flex-row justify-between items-center gap-4 bg-slate-900/60 p-4 rounded-2xl border border-slate-800 no-print">
                    
                    <!-- Search Input -->
                    <div class="relative w-full sm:w-72">
                        <i class="fa-solid fa-magnifying-glass absolute left-3.5 top-3 text-slate-500 text-xs"></i>
                        <input type="text" id="adminSearchInput" oninput="renderAdminTable()" placeholder="Cari nama, tim, sekolah..." class="w-full pl-9 pr-4 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs text-slate-100 focus:outline-none focus:border-amber-400">
                    </div>

                    <!-- Filters -->
                    <div class="flex flex-wrap items-center gap-2 w-full sm:w-auto">
                        <select id="adminFilterType" onchange="renderAdminTable()" class="px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs text-slate-200 focus:outline-none">
                            <option value="ALL">Semua Jenis Pendaftaran</option>
                            <option value="Workshop">Workshop AI (Gratis)</option>
                            <option value="Lomba Mobile">Lomba Mobile Apps</option>
                            <option value="Lomba Website">Lomba Website AI</option>
                        </select>

                        <select id="adminFilterStatus" onchange="renderAdminTable()" class="px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs text-slate-200 focus:outline-none">
                            <option value="ALL">Semua Status</option>
                            <option value="Terverifikasi">Terverifikasi</option>
                            <option value="Pending">Pending</option>
                        </select>


                    </div>

                </div>

                <!-- DATA TABLE -->
                <div class="overflow-x-auto rounded-2xl border border-slate-800 bg-slate-900/40">
                    <table class="w-full text-left border-collapse text-xs">
                        <thead>
                            <tr class="bg-slate-800/80 text-amber-400 font-bold border-b border-slate-700">
                                <th class="p-3">ID Reg</th>
                                <th class="p-3">Tanggal</th>
                                <th class="p-3">Peserta / Tim</th>
                                <th class="p-3">Sekolah / Instansi</th>
                                <th class="p-3">Jenis Program</th>
                                <th class="p-3">Kontak (WA/Email)</th>
                                <th class="p-3">Status</th>
                                <th class="p-3 no-print text-center">Aksi</th>
                            </tr>
                        </thead>
                        <tbody id="adminTableBody" class="divide-y divide-slate-800/60 text-slate-300">
                            <!-- Dynamic Content -->
                        </tbody>
                    </table>
                </div>

            </div>

        </div>
    </div>

    <!-- CUSTOM TOAST NOTIFICATION CONTAINER -->
    <div id="toastContainer" class="fixed bottom-5 right-5 z-50 flex flex-col gap-2 pointer-events-none"></div>

    <script>
        let isAdminLoggedIn = false;
        let registrationCache = [];

        window.addEventListener('DOMContentLoaded', () => {
            startCountdownTimer();
            toggleFormFields();
            checkAdminSession();
        });

        async function api(action, payload = {}, method = 'POST') {
            const options = { method, headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' } };
            if (method !== 'GET') options.body = JSON.stringify(payload);
            const apiUrl = `${window.location.pathname}?action=${encodeURIComponent(action)}`;
            const response = await fetch(apiUrl, options);
            let result;
            try { result = await response.json(); } catch (_) { throw new Error('Respons server tidak valid. Periksa konfigurasi PHP dan database.'); }
            if (!response.ok || result.success === false) throw new Error(result.message || 'Permintaan gagal.');
            return result;
        }

        function startCountdownTimer() {
            const targetDate = new Date('2026-11-25T08:00:00+08:00').getTime();
            function updateTimer() {
                const diff = targetDate - Date.now();
                const values = diff <= 0 ? [0,0,0,0] : [
                    Math.floor(diff / 86400000),
                    Math.floor((diff % 86400000) / 3600000),
                    Math.floor((diff % 3600000) / 60000),
                    Math.floor((diff % 60000) / 1000)
                ];
                ['cd-days','cd-hours','cd-minutes','cd-seconds'].forEach((id, i) => {
                    const el = document.getElementById(id);
                    if (el) el.innerText = String(values[i]).padStart(2, '0');
                });
            }
            updateTimer(); setInterval(updateTimer, 1000);
        }

        function toggleMobileMenu() {
            const menu = document.getElementById('mobileMenu');
            if (menu) menu.classList.toggle('hidden');
        }

        function currentRegistrationType() {
            const selected = document.querySelector('input[name="regType"]:checked')?.value || 'Workshop';
            return selected === 'Workshop' ? 'Workshop' : document.getElementById('competitionCategory').value;
        }

        function toggleFormFields() {
            const selected = document.querySelector('input[name="regType"]:checked')?.value || 'Workshop';
            const isCompetition = selected === 'Lomba';
            document.getElementById('teamSection').classList.toggle('hidden', !isCompetition);
            document.getElementById('paymentNotice').classList.toggle('hidden', !isCompetition);
            document.getElementById('competitionLinkSection').classList.toggle('hidden', !isCompetition);
            document.getElementById('competitionCategorySection').classList.toggle('hidden', !isCompetition);
            document.getElementById('labelParticipantName').innerHTML = isCompetition
                ? 'Nama Tim / Ketua Tim <span class="text-amber-400">*</span>'
                : 'Nama Lengkap Peserta <span class="text-amber-400">*</span>';
            if (!isCompetition) {
                document.getElementById('regMember1').value = '';
                document.getElementById('regMember2').value = '';
                document.getElementById('regLink').value = '';
                document.getElementById('regPaymentProof').value = '';
            }
            updateCompetitionLabel();
        }

        function updateCompetitionLabel() {
            const category = document.getElementById('competitionCategory')?.value || 'Lomba Mobile';
            const label = document.getElementById('competitionLinkLabel');
            if (label) label.textContent = category === 'Lomba Mobile'
                ? 'Link Aplikasi / Repositori (Google Drive / GitHub / Figma)'
                : 'Link Website / Repositori (Google Drive / GitHub / Figma)';
        }

        function selectRegistrationType(typeKey) {
            document.getElementById('pendaftaran').scrollIntoView({ behavior: 'smooth' });
            if (typeKey === 'workshop') {
                document.querySelector('input[name="regType"][value="Workshop"]').checked = true;
            } else {
                document.querySelector('input[name="regType"][value="Lomba"]').checked = true;
                document.getElementById('competitionCategory').value = typeKey === 'lomba_web' ? 'Lomba Website' : 'Lomba Mobile';
            }
            toggleFormFields();
        }

        async function handleRegistrationSubmit(e) {
            e.preventDefault();
            const regType = currentRegistrationType();
            const payload = {
                type: regType,
                name: document.getElementById('regName').value.trim(),
                institution: document.getElementById('regInstitution').value.trim(),
                email: document.getElementById('regEmail').value.trim(),
                whatsapp: document.getElementById('regWhatsapp').value.trim(),
                member1: regType === 'Workshop' ? '' : document.getElementById('regMember1').value.trim(),
                member2: regType === 'Workshop' ? '' : document.getElementById('regMember2').value.trim(),
                link: regType === 'Workshop' ? '' : document.getElementById('regLink').value.trim(),
                proof: regType === 'Workshop' ? '' : document.getElementById('regPaymentProof').value.trim()
            };
            try {
                const result = await api('register', payload);
                document.getElementById('registrationForm').reset();
                toggleFormFields();
                showToast('Pendaftaran Berhasil!', `Terima kasih ${payload.name}. ID Pendaftaran Anda adalah ${result.registration_code}.`);
                if (isAdminLoggedIn) await renderAdminTable();
            } catch (err) {
                showToast('Pendaftaran Gagal', err.message);
            }
        }

        function handleAdminBtnClick() {
            if (isAdminLoggedIn) openAdminDashboardModal(); else openAdminLoginModal();
        }
        function openAdminLoginModal() {
            document.getElementById('adminLoginModal').classList.remove('hidden');
            document.getElementById('loginErrorMsg').classList.add('hidden');
        }
        function closeAdminLoginModal() { document.getElementById('adminLoginModal').classList.add('hidden'); }
        async function openAdminDashboardModal() {
            document.getElementById('adminDashboardModal').classList.remove('hidden');
            await renderAdminTable();
        }
        function closeAdminDashboardModal() { document.getElementById('adminDashboardModal').classList.add('hidden'); }

        async function handleAdminLogin(e) {
            e.preventDefault();
            const user = document.getElementById('adminUsername').value.trim();
            const pass = document.getElementById('adminPassword').value;
            try {
                await api('login', { username: user, password: pass });
                isAdminLoggedIn = true;
                updateAdminNavUI(); closeAdminLoginModal();
                await openAdminDashboardModal();
                showToast('Login Admin Berhasil', 'Selamat datang di Panel Administrasi NAISC 2026.');
            } catch (err) {
                const errBox = document.getElementById('loginErrorMsg');
                errBox.innerText = err.message;
                errBox.classList.remove('hidden');
            }
        }

        async function checkAdminSession() {
            try {
                const result = await api('session', {}, 'GET');
                isAdminLoggedIn = !!result.authenticated;
                updateAdminNavUI();
            } catch (_) { isAdminLoggedIn = false; updateAdminNavUI(); }
        }

        async function handleAdminLogout() {
            try { await api('logout', {}); } catch (_) {}
            isAdminLoggedIn = false;
            updateAdminNavUI(); closeAdminDashboardModal();
            showToast('Logout Admin', 'Anda telah keluar dari mode admin.');
        }

        function updateAdminNavUI() {
            const btnLabel = document.getElementById('adminBtnLabel');
            const openBtn = document.getElementById('openAdminBtn');
            if (!btnLabel || !openBtn) return;
            if (isAdminLoggedIn) {
                btnLabel.innerHTML = 'Mode Admin Aktif';
                openBtn.className = 'flex items-center gap-2 px-4 py-2 rounded-xl text-xs sm:text-sm font-semibold transition-all duration-300 bg-amber-500 text-navy-900 border border-amber-400 shadow-lg shadow-amber-500/20';
            } else {
                btnLabel.innerHTML = 'Akses Admin';
                openBtn.className = 'flex items-center gap-2 px-4 py-2 rounded-xl text-xs sm:text-sm font-semibold transition-all duration-300 bg-gradient-to-r from-amber-500/20 via-amber-500/10 to-transparent border border-amber-500/50 text-amber-300 hover:bg-amber-500 hover:text-navy-900 shadow-lg shadow-amber-500/10 hover:shadow-amber-500/30';
            }
        }

        function escapeHtml(value) {
            return String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
        }

        async function renderAdminTable() {
            if (!isAdminLoggedIn) return;
            const tbody = document.getElementById('adminTableBody');
            try {
                const result = await api('list', {}, 'GET');
                registrationCache = result.data || [];
            } catch (err) {
                tbody.innerHTML = `<tr><td colspan="8" class="p-6 text-center text-rose-300">${escapeHtml(err.message)}</td></tr>`;
                return;
            }
            const data = registrationCache;
            const searchQuery = document.getElementById('adminSearchInput').value.toLowerCase().trim();
            const filterType = document.getElementById('adminFilterType').value;
            const filterStatus = document.getElementById('adminFilterStatus').value;
            document.getElementById('statTotal').innerText = data.length;
            document.getElementById('statWorkshop').innerText = data.filter(x => x.type === 'Workshop').length;
            document.getElementById('statMobile').innerText = data.filter(x => x.type === 'Lomba Mobile').length;
            document.getElementById('statWeb').innerText = data.filter(x => x.type === 'Lomba Website').length;
            const revenue = data.filter(x => x.type !== 'Workshop' && x.status === 'Terverifikasi').reduce((sum, x) => sum + Number(x.registration_fee || 0), 0);
            document.getElementById('statRevenue').innerText = 'Rp ' + revenue.toLocaleString('id-ID');
            const filtered = data.filter(item => {
                const q = `${item.name} ${item.institution} ${item.id} ${item.email}`.toLowerCase();
                return q.includes(searchQuery) && (filterType === 'ALL' || item.type === filterType) && (filterStatus === 'ALL' || item.status === filterStatus);
            });
            tbody.innerHTML = '';
            if (!filtered.length) {
                tbody.innerHTML = '<tr><td colspan="8" class="p-6 text-center text-slate-500 italic">Tidak ada data pendaftaran yang sesuai kriteria filter.</td></tr>';
                return;
            }
            filtered.forEach(item => {
                const tr = document.createElement('tr');
                tr.className = 'hover:bg-slate-800/40 transition-colors';
                const statusBadge = item.status === 'Terverifikasi'
                    ? '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">Terverifikasi</span>'
                    : `<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">${escapeHtml(item.status)}</span>`;
                tr.innerHTML = `
                    <td class="p-3 font-mono text-amber-400 font-bold">${escapeHtml(item.id)}</td>
                    <td class="p-3 text-slate-400 text-[11px]">${escapeHtml(item.date)}</td>
                    <td class="p-3"><div class="font-bold text-slate-100">${escapeHtml(item.name)}</div>${item.members && item.members !== '-' ? `<div class="text-[10px] text-slate-400">${escapeHtml(item.members)}</div>` : ''}</td>
                    <td class="p-3 text-slate-300">${escapeHtml(item.institution)}</td>
                    <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] font-semibold ${item.type === 'Workshop' ? 'bg-cyan-500/20 text-cyan-300' : 'bg-purple-500/20 text-purple-300'}">${escapeHtml(item.type)}</span></td>
                    <td class="p-3"><div>${escapeHtml(item.whatsapp)}</div><div class="text-[10px] text-slate-400">${escapeHtml(item.email)}</div></td>
                    <td class="p-3">${statusBadge}</td>
                    <td class="p-3 no-print text-center space-x-1"><button onclick="toggleVerificationStatus('${escapeHtml(item.id)}')" title="Ubah Status" class="p-1.5 rounded-lg bg-slate-800 hover:bg-amber-500 hover:text-navy-900 text-amber-400 transition-all"><i class="fa-solid fa-rotate"></i></button><button onclick="deleteRecord('${escapeHtml(item.id)}')" title="Hapus" class="p-1.5 rounded-lg bg-slate-800 hover:bg-rose-500 hover:text-white text-rose-400 transition-all"><i class="fa-solid fa-trash"></i></button></td>`;
                tbody.appendChild(tr);
            });
        }

        async function toggleVerificationStatus(code) {
            try { await api('toggle_status', { registration_code: code }); await renderAdminTable(); showToast('Status Diperbarui', `Status pendaftaran ${code} berhasil diperbarui.`); }
            catch (err) { showToast('Gagal Memperbarui Status', err.message); }
        }
        async function deleteRecord(code) {
            if (!confirm(`Apakah Anda yakin ingin menghapus data pendaftaran ${code}?`)) return;
            try { await api('delete', { registration_code: code }); await renderAdminTable(); showToast('Data Dihapus', `Pendaftaran ${code} telah dihapus.`); }
            catch (err) { showToast('Gagal Menghapus Data', err.message); }
        }

        async function exportDataCSV() {
            try {
                const result = await api('list', {}, 'GET');
                const data = result.data || [];
                if (!data.length) { showToast('Peringatan', 'Tidak ada data untuk diekspor.'); return; }
                const cols = ['id','date','name','institution','type','email','whatsapp','members','link','proof','payment_status','status'];
                const labels = ['ID Pendaftaran','Tanggal','Nama Tim/Peserta','Sekolah/Instansi','Jenis Program','Email','WhatsApp','Anggota','Link Karya','Bukti Pembayaran','Status Pembayaran','Status Verifikasi'];
                const cell = v => '"' + String(v ?? '').replace(/"/g, '""') + '"';
                const csv = '\uFEFF' + labels.map(cell).join(',') + '\n' + data.map(item => cols.map(k => cell(item[k])).join(',')).join('\n');
                const blob = new Blob([csv], {type:'text/csv;charset=utf-8;'});
                const url = URL.createObjectURL(blob); const a = document.createElement('a');
                a.href = url; a.download = `Pendaftar_NAISC_2026_${new Date().toISOString().slice(0,10)}.csv`; a.click(); URL.revokeObjectURL(url);
                showToast('Ekspor Berhasil', 'File CSV berhasil diunduh.');
            } catch (err) { showToast('Ekspor Gagal', err.message); }
        }
        async function exportDataJSON() {
            try {
                const result = await api('list', {}, 'GET');
                const blob = new Blob([JSON.stringify(result.data || [], null, 2)], {type:'application/json'});
                const url = URL.createObjectURL(blob); const a = document.createElement('a');
                a.href = url; a.download = `Pendaftar_NAISC_2026_${new Date().toISOString().slice(0,10)}.json`; a.click(); URL.revokeObjectURL(url);
                showToast('Ekspor Berhasil', 'File JSON backup berhasil diunduh.');
            } catch (err) { showToast('Ekspor Gagal', err.message); }
        }
        function printAdminReport() { window.print(); }

        function showToast(title, message) {
            const container = document.getElementById('toastContainer');
            const toast = document.createElement('div');
            toast.className = 'glass-panel p-4 rounded-2xl shadow-2xl border border-amber-500/40 flex items-start gap-3 min-w-[280px] max-w-sm pointer-events-auto transform translate-y-2 opacity-0 transition-all duration-300';
            const iconBox = document.createElement('div'); iconBox.className = 'p-2 bg-amber-500/20 text-amber-400 rounded-xl'; iconBox.innerHTML = '<i class="fa-solid fa-bell"></i>';
            const content = document.createElement('div'); content.className = 'flex-grow';
            const heading = document.createElement('h5'); heading.className = 'font-bold text-xs text-slate-100'; heading.textContent = title;
            const messageEl = document.createElement('p'); messageEl.className = 'text-[11px] text-slate-300 mt-0.5'; messageEl.textContent = message;
            content.append(heading, messageEl); toast.append(iconBox, content); container.appendChild(toast);
            requestAnimationFrame(() => toast.classList.remove('opacity-0', 'translate-y-2'));
            setTimeout(() => { toast.classList.add('opacity-0', 'translate-y-2'); setTimeout(() => toast.remove(), 300); }, 4000);
        }
    </script>
</body>
</html>
