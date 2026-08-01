<?php
session_start();
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) { header("Location: login.html"); exit; }
$role = $_SESSION['role'] ?? 'user';
$username = $_SESSION['username'] ?? 'User';
$expiration = $_SESSION['expiration'] ?? 0;
if ($role !== 'admin' && $expiration !== -1 && time() > $expiration) { session_destroy(); header("Location: login.html?msg=expired"); exit; }
$is_admin = ($role === 'admin');
$expiration_date = ($is_admin || $expiration === -1) ? "∞ Sem expiração" : date('d/m/Y H:i', $expiration);
session_write_close();
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kroenen Engine — Checker</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg:       #020205;
            --surface:  #0d0d12;
            --surface2: #13131a;
            --border:   rgba(255,255,255,0.07);
            --border-hi:rgba(255,255,255,0.13);
            --text:     #f0f0f5;
            --muted:    #6b7280;
            --accent:   #7c3aed;
            --accent-hi:#9f5cf7;
            --success:  #10b981;
            --success-bg:rgba(16,185,129,0.08);
            --danger:   #ef4444;
            --danger-bg:rgba(239,68,68,0.08);
            --radius:   14px;
        }
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            -webkit-font-smoothing: antialiased;
        }
        body::before {
            content:'';position:fixed;inset:0;
            background-image: linear-gradient(rgba(124,58,237,.03) 1px,transparent 1px),linear-gradient(90deg,rgba(124,58,237,.03) 1px,transparent 1px);
            background-size:48px 48px;z-index:0;pointer-events:none;
        }
        nav {
            position: sticky; top: 0; z-index: 50;
            display: flex; justify-content: space-between; align-items: center;
            padding: 0 2rem; height: 64px;
            background: rgba(2,2,5,0.85);
            backdrop-filter: blur(16px);
            border-bottom: 1px solid var(--border);
        }
        .nav-brand { display:flex; align-items:center; gap:.7rem; text-decoration:none; }
        .nav-icon {
            width:34px;height:34px;background:linear-gradient(135deg,var(--accent),#4f46e5);
            border-radius:8px;display:flex;align-items:center;justify-content:center;
            box-shadow:0 0 18px rgba(124,58,237,.45);
        }
        .nav-icon svg { width:18px;height:18px;stroke:#fff;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round; }
        .nav-title { font-size:1rem;font-weight:700;letter-spacing:-.02em;color:var(--text); }
        .nav-right { display:flex;align-items:center;gap:.75rem; }
        .user-chip {
            display:flex;align-items:center;gap:.6rem;
            background:var(--surface2);border:1px solid var(--border);
            border-radius:9999px;padding:.35rem .9rem .35rem .4rem;
        }
        .user-avatar {
            width:28px;height:28px;border-radius:50%;
            background:linear-gradient(135deg,var(--accent),#4f46e5);
            display:flex;align-items:center;justify-content:center;
            font-size:.75rem;font-weight:700;color:#fff;
        }
        .user-name { font-size:.85rem;font-weight:500; }
        .user-exp  { font-size:.72rem;color:var(--muted); }
        .btn {
            display:inline-flex;align-items:center;gap:.4rem;
            padding:.45rem .9rem;font-size:.8rem;font-weight:500;
            border-radius:9999px;cursor:pointer;transition:all .2s;
            text-decoration:none;border:1px solid var(--border);
            background:var(--surface2);color:var(--text);
        }
        .btn:hover { border-color:var(--border-hi);background:rgba(255,255,255,.05); }
        .btn-danger { background:var(--danger-bg);border-color:rgba(239,68,68,.25);color:var(--danger); }
        .btn-danger:hover { background:rgba(239,68,68,.15); }
        .btn-admin { background:rgba(124,58,237,.12);border-color:rgba(124,58,237,.3);color:var(--accent-hi); }
        .btn-admin:hover { background:rgba(124,58,237,.2); }
        main { max-width:1100px;margin:0 auto;padding:2.5rem 1.5rem; position:relative;z-index:1; }
        .hero { text-align:center;margin-bottom:2.5rem;animation:rise .5s ease both; }
        .hero h1 { font-size:2.6rem;font-weight:800;letter-spacing:-.05em;line-height:1.1; }
        .hero h1 span { background:linear-gradient(135deg,var(--accent-hi),#818cf8);-webkit-background-clip:text;-webkit-text-fill-color:transparent; }
        .hero p { color:var(--muted);margin-top:.5rem;font-size:.95rem; }
        .stats { display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:1.5rem; }
        .stat-card {
            background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
            padding:1.2rem 1.4rem;display:flex;align-items:center;gap:1rem;
            transition:border-color .2s;
        }
        .stat-card:hover { border-color:var(--border-hi); }
        .stat-icon { width:40px;height:40px;border-radius:10px;display:flex;align-items:center;justify-content:center; }
        .stat-icon svg { width:20px;height:20px;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;fill:none; }
        .stat-label { font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:.2rem; }
        .stat-val { font-size:1.6rem;font-weight:700;letter-spacing:-.04em;line-height:1; }
        .control-panel {
            background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
            padding:1.8rem;margin-bottom:1.5rem;
        }
        .cp-title { font-size:.75rem;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:1.2rem; }
        .upload-zone {
            border:1.5px dashed var(--border-hi);border-radius:var(--radius);
            padding:1.5rem;text-align:center;cursor:pointer;
            transition:border-color .2s,background .2s;margin-bottom:1.2rem;
            background:rgba(124,58,237,.02);
        }
        .upload-zone:hover,.upload-zone.dragover { border-color:var(--accent);background:rgba(124,58,237,.06); }
        .upload-zone svg { width:32px;height:32px;stroke:var(--muted);stroke-width:1.5;fill:none;margin-bottom:.6rem; }
        .upload-zone p { font-size:.85rem;color:var(--muted); }
        .upload-zone strong { color:var(--text); }
        .upload-zone input[type=file] { display:none; }
        .file-name { font-size:.82rem;color:var(--accent-hi);margin-top:.4rem;font-weight:500; }
        .run-row { display:flex;gap:1rem;align-items:center; }
        .btn-start {
            flex:1;padding:.85rem;background:linear-gradient(135deg,var(--accent),#4f46e5);
            color:#fff;border:none;border-radius:var(--radius);font-size:.9rem;font-weight:600;
            cursor:pointer;transition:opacity .2s,transform .15s,box-shadow .2s;
            box-shadow:0 4px 20px rgba(124,58,237,.35);display:flex;align-items:center;justify-content:center;gap:.5rem;
        }
        .btn-start:hover:not(:disabled) { opacity:.9;transform:translateY(-1px);box-shadow:0 8px 28px rgba(124,58,237,.45); }
        .btn-start:disabled { opacity:.45;cursor:not-allowed; }
        .btn-start svg { width:18px;height:18px;stroke:#fff;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round; }
        .progress-wrap { margin-top:1.2rem; }
        .progress-bar-bg { height:5px;background:var(--border);border-radius:9999px;overflow:hidden;margin-bottom:.6rem; }
        .progress-bar { height:100%;background:linear-gradient(90deg,var(--accent),#818cf8);width:0%;transition:width .3s ease;border-radius:9999px; }
        .progress-label { font-size:.8rem;color:var(--muted);display:flex;justify-content:space-between; }
        .results { display:grid;grid-template-columns:1fr 1fr;gap:1.5rem; }
        @media(max-width:640px){.results,.stats{grid-template-columns:1fr;}}
        .result-panel {
            background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
            display:flex;flex-direction:column;overflow:hidden;
        }
        .rp-header {
            display:flex;justify-content:space-between;align-items:center;
            padding:.9rem 1.2rem;border-bottom:1px solid var(--border);
        }
        .rp-title { display:flex;align-items:center;gap:.5rem;font-size:.875rem;font-weight:600; }
        .dot { width:8px;height:8px;border-radius:50%;flex-shrink:0; }
        .dot-live { background:var(--success);box-shadow:0 0 8px var(--success); }
        .dot-die  { background:var(--danger);box-shadow:0 0 8px var(--danger); }
        .rp-badge { padding:.15rem .55rem;border-radius:9999px;font-size:.72rem;font-weight:700; }
        .badge-live { background:var(--success-bg);color:var(--success); }
        .badge-die  { background:var(--danger-bg);color:var(--danger); }
        .log-box {
            flex:1;padding:1rem;height:320px;overflow-y:auto;
            font-family:'Consolas',monospace;font-size:.78rem;color:var(--muted);
            background:#000;
        }
        .log-box div { padding:.25rem 0;border-bottom:1px solid rgba(255,255,255,.03);word-break:break-all; }
        .live-text { color:var(--success) !important; }
        .die-text  { color:var(--danger) !important; }
        .rp-footer { padding:.8rem 1rem;border-top:1px solid var(--border); }
        .btn-dl {
            width:100%;padding:.6rem;border-radius:var(--radius);border:1px solid;
            font-size:.8rem;font-weight:600;cursor:pointer;text-align:center;text-decoration:none;display:block;
            transition:background .2s;
        }
        .btn-dl-live { background:var(--success-bg);border-color:rgba(16,185,129,.25);color:var(--success); }
        .btn-dl-live:hover { background:rgba(16,185,129,.15); }
        .btn-dl-die  { background:var(--danger-bg);border-color:rgba(239,68,68,.25);color:var(--danger); }
        .btn-dl-die:hover  { background:rgba(239,68,68,.15); }
        ::-webkit-scrollbar{width:4px;} ::-webkit-scrollbar-track{background:transparent;} ::-webkit-scrollbar-thumb{background:rgba(255,255,255,.1);border-radius:4px;}
        @keyframes rise{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
    </style>
</head>
<body>
<nav>
    <a href="#" class="nav-brand">
        <div class="nav-icon">
            <svg viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 
