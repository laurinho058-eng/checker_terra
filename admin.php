<?php
session_start();
if (!isset($_SESSION['logged_in']) || $_SESSION['role'] !== 'admin') { header("Location: login.html"); exit; }
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kroenen Engine — Admin</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg:       #020205;
            --surface:  #0d0d12;
            --surface2: #13131a;
            --border:   rgba(255,255,255,0.07);
            --border-hi:rgba(255,255,255,0.14);
            --text:     #f0f0f5;
            --muted:    #6b7280;
            --accent:   #7c3aed;
            --accent-hi:#9f5cf7;
            --success:  #10b981;
            --success-bg:rgba(16,185,129,0.1);
            --danger:   #ef4444;
            --danger-bg:rgba(239,68,68,0.1);
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
            content:''; position:fixed; inset:0;
            background-image: linear-gradient(rgba(124,58,237,.03) 1px,transparent 1px),linear-gradient(90deg,rgba(124,58,237,.03) 1px,transparent 1px);
            background-size:48px 48px; z-index:0; pointer-events:none;
        }

        /* NAV */
        nav {
            position:sticky; top:0; z-index:50;
            display:flex; justify-content:space-between; align-items:center;
            padding:0 2rem; height:64px;
            background:rgba(2,2,5,.88); backdrop-filter:blur(16px);
            border-bottom:1px solid var(--border);
        }
        .nav-brand { display:flex; align-items:center; gap:.7rem; text-decoration:none; }
        .nav-icon {
            width:34px;height:34px;background:linear-gradient(135deg,var(--accent),#4f46e5);
            border-radius:8px;display:flex;align-items:center;justify-content:center;
            box-shadow:0 0 18px rgba(124,58,237,.45);
        }
        .nav-icon svg { width:18px;height:18px;stroke:#fff;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round; }
        .nav-title { font-size:1rem;font-weight:700;letter-spacing:-.02em;color:var(--text); }
        .nav-tag { font-size:.7rem;letter-spacing:.08em;text-transform:uppercase;color:var(--accent-hi);
            background:rgba(124,58,237,.15);border:1px solid rgba(124,58,237,.25);border-radius:9999px;padding:.1rem .5rem;margin-left:.5rem; }
        .nav-right { display:flex; align-items:center; gap:.75rem; }

        .btn {
            display:inline-flex;align-items:center;gap:.4rem;
            padding:.45rem .9rem;font-size:.8rem;font-weight:500;
            border-radius:9999px;cursor:pointer;transition:all .2s;
            text-decoration:none;border:1px solid var(--border);
            background:var(--surface2);color:var(--text);
        }
        .btn:hover { border-color:var(--border-hi);background:rgba(255,255,255,.05); }
        .btn-danger-sm { background:var(--danger-bg);border-color:rgba(239,68,68,.25);color:var(--danger); }
        .btn-danger-sm:hover { background:rgba(239,68,68,.15); }
        .btn-sm { padding:.3rem .7rem;font-size:.75rem; }

        /* MAIN */
        main { max-width:1100px;margin:0 auto;padding:2.5rem 1.5rem;position:relative;z-index:1; }

        /* PAGE HEADER */
        .page-header { display:flex;justify-content:space-between;align-items:flex-end;margin-bottom:2.5rem; }
        .page-header h1 { font-size:1.9rem;font-weight:800;letter-spacing:-.05em; }
        .page-header p { color:var(--muted);font-size:.875rem;margin-top:.25rem; }

        /* CARDS / SECTIONS */
        .section { margin-bottom:2rem; }
        .section-label { font-size:.72rem;font-weight:600;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:1rem; }

        .card {
            background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
            padding:1.8rem;box-shadow:0 8px 32px rgba(0,0,0,.4);
        }

        /* FORM */
        .form-grid {
            display:grid;
            grid-template-columns:repeat(auto-fit,minmax(170px,1fr));
            gap:1.2rem; align-items:end;
        }
        .form-group { display:flex;flex-direction:column;gap:.45rem; }
        .form-group label { font-size:.75rem;font-weight:500;color:var(--muted);text-transform:uppercase;letter-spacing:.05em; }
        input,select,textarea {
            width:100%;padding:.7rem 1rem;font-size:.875rem;font-family:inherit;
            color:var(--text);background:rgba(255,255,255,.03);
            border:1px solid var(--border);border-radius:10px;
            transition:border-color .2s,box-shadow .2s,background .2s;outline:none;
        }
        input:focus,select:focus,textarea:focus {
            border-color:var(--accent);background:rgba(124,58,237,.05);box-shadow:0 0 0 3px rgba(124,58,237,.15);
        }
        input::placeholder { color:rgba(107,114,128,.5); }
        select option { background:#1a1a24; }

        .btn-primary {
            padding:.72rem 1.4rem;background:linear-gradient(135deg,var(--accent),#4f46e5);
            color:#fff;border:none;border-radius:10px;font-size:.875rem;font-weight:600;
            cursor:pointer;transition:opacity .2s,transform .15s,box-shadow .2s;
            box-shadow:0 4px 16px rgba(124,58,237,.35);white-space:nowrap;
            display:inline-flex;align-items:center;justify-content:center;width:100%;height:42px;
        }
        .btn-primary:hover:not(:disabled) { opacity:.9;transform:translateY(-1px);box-shadow:0 8px 24px rgba(124,58,237,.45); }
        .btn-primary:disabled { opacity:.4;cursor:not-allowed; }

        /* TABLE */
        .table-wrap {
            background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
            overflow:hidden;
        }
        table { width:100%;border-collapse:collapse; }
        thead { background:rgba(255,255,255,.025); }
        th {
            padding:.8rem 1.2rem;text-align:left;font-size:.7rem;font-weight:600;
            text-transform:uppercase;letter-spacing:.07em;color:var(--muted);
            border-bottom:1px solid var(--border);
        }
        td { padding:.9rem 1.2rem;font-size:.875rem;border-bottom:1px solid var(--border); }
        tr:last-child td { border-bottom:none; }
        tbody tr { transition:background .15s; }
        tbody tr:hover { background:rgba(255,255,255,.02); }

        .td-actions { display:flex;gap:.5rem; }

        /* BADGES */
        .badge {
            display:inline-flex;align-items:center;padding:.2rem .6rem;
            border-radius:9999px;font-size:.72rem;font-weight:700;letter-spacing:.03em;
        }
        .badge-admin   { background:rgba(124,58,237,.15);color:var(--accent-hi);border:1px solid rgba(124,58,237,.25); }
        .badge-success { background:var(--success-bg);color:var(--success);border:1px solid rgba(16,185,129,.2); }
        .badge-expired { background:var(--danger-bg);color:var(--danger);border:1px solid rgba(239,68,68,.2); }
        .role-badge { transition:all .2s; }
        .role-badge[onclick] { cursor:pointer; }
        .role-badge[onclick]:hover { filter:brightness(1.25);transform:scale(1.06); }

        /* MODALS */
        .modal-overlay {
            position:fixed;inset:0;background:rgba(0,0,0,.75);backdrop-filter:blur(8px);
            display:flex;align-items:center;justify-content:center;z-index:100;
            opacity:0;pointer-events:none;transition:opacity .2s;
        }
        .modal-overlay.active { opacity:1;pointer-events:auto; }
        .modal {
            background:var(--surface);border:1px solid var(--border-hi);border-radius:18px;
            padding:2rem;width:100%;max-width:460px;
            box-shadow:0 32px 80px rgba(0,0,0,.6);
            transform:scale(.96) translateY(12px);transition:transform .25s,opacity .25s;
        }
        .modal-overlay.active .modal { transform:scale(1) translateY(0); }
        .modal-header { display:flex;justify-content:space-between;align-items:center;margin-bottom:1.5rem; }
        .modal-title { font-size:1.1rem;font-weight:700; }
        .modal-close {
            background:transparent;border:none;color:var(--muted);font-size:1.4rem;
            cursor:pointer;line-height:1;transition:color .2s;
        }
        .modal-close:hover { color:var(--text); }
        .modal-group { margin-bottom:1.2rem; }
        .modal-group label { display:block;font-size:.75rem;font-weight:500;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:.45rem; }

        /* Copy box */
        .copy-box {
            width:100%;padding:1rem;background:#000;border:1px solid var(--border);
            border-radius:10px;color:var(--muted);font-family:'Consolas',monospace;font-size:.82rem;
            white-space:pre-wrap;resize:none;height:160px;margin-bottom:1.2rem;line-height:1.6;
        }
        .copy-box:focus { border-color:var(--accent);outline:none; }

        /* SUCCESS icon */
        .success-icon { display:flex;align-items:center;gap:.6rem;color:var(--success);margin-bottom:1rem; }
        .success-icon svg { width:22px;height:22px;stroke:currentColor;fill:none;stroke-width:2; }

        ::-webkit-scrollbar{width:4px;} ::-webkit-scrollbar-track{background:transparent;} ::-webkit-scrollbar-thumb{background:rgba(255,255,255,.1);border-radius:4px;}
    </style>
</head>
<body>
<nav>
    <a class="nav-brand" href="#">
        <div class="nav-icon">
            <svg viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
        </div>
        <span class="nav-title">Kroenen Engine</span>
        <span class="nav-tag">Admin</span>
    </a>
    <div class="nav-right">
        <a href="index.php" class="btn">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>
            Checker
        </a>
        <button class="btn btn-danger-sm" onclick="logout()">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
            Sair
        </button>
    </div>
</nav>

<main>
    <div class="page-header">
        <div>
            <h1>System Management</h1>
            <p>Painel de controle de acessos e usuários</p>
        </div>
    </div>

    <!-- Provision -->
    <div class="section">
        <div class="section-label">⚡ Provisionar Novo Usuário</div>
        <div class="card">
            <form id="createUserForm">
                <div class="form-grid">
                    <div class="form-group">
                        <label>Usuário</label>
                        <input type="text" id="new_username" placeholder="john.doe" required autocomplete="off">
                    </div>
                    <div class="form-group">
                        <label>Senha</label>
                        <input type="text" id="new_password" placeholder="Senha segura" required autocomplete="off">
                    </div>
                    <div class="form-group">
                        <label>Plano</label>
                        <select id="plan">
                            <option value="1">24 Horas (Trial)</option>
                            <option value="7">7 Dias</option>
                            <option value="15">15 Dias</option>
                            <option value="30">30 Dias</option>
                            <option value="0">∞ Infinito</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Perfil</label>
                        <select id="new_role">
                            <option value="user">Membro</option>
                            <option value="admin">Administrador</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <button type="submit" class="btn-primary">Criar Conta</button>
                    </div>
                </div>
            </form>
        </div>
    </div>

    <!-- Directory -->
    <div class="section">
        <div class="section-label">👥 Diretório Ativo</div>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Usuário</th>
                        <th>Perfil</th>
                        <th>Criado em</th>
                        <th>Expiração</th>
                        <th>Ações</th>
                    </tr>
                </thead>
                <tbody id="usersList"></tbody>
            </table>
        </div>
    </div>
</main>

<!-- Edit Modal -->
<div class="modal-overlay" id="editModal">
    <div class="modal">
        <div class="modal-header">
            <div class="modal-title">Editar <span id="editTargetUser" style="color:var(--muted);font-weight:400;margin-left:.4rem;font-size:.95rem;"></span></div>
            <button class="modal-close" onclick="closeModal('editModal')">&times;</button>
        </div>
        <form id="editUserForm">
            <input type="hidden" id="edit_username">
            <input type="hidden" id="edit_role">
            <div class="modal-group">
                <label>Nova Senha</label>
                <input type="text" id="edit_password" placeholder="Deixe em branco para manter">
            </div>
            <div class="modal-group" id="extendPlanGroup">
                <label>Estender Assinatura</label>
                <select id="extend_days">
                    <option value="0">Sem alteração</option>
                    <option value="1">+ 24 Horas</option>
                    <option value="7">+ 7 Dias</option>
                    <option value="15">+ 15 Dias</option>
                    <option value="30">+ 30 Dias</option>
                </select>
            </div>
            <button type="submit" class="btn-primary">Salvar Alterações</button>
        </form>
    </div>
</div>

<!-- Success Modal -->
<div class="modal-overlay" id="successModal">
    <div class="modal">
        <div class="modal-header">
            <div class="modal-title">
                <div class="success-icon">
                    <svg viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                    Conta Provisionada
                </div>
            </div>
            <button class="modal-close" onclick="closeModal('successModal')">&times;</button>
        </div>
        <p style="color:var(--muted);font-size:.85rem;margin-bottom:1rem;">Copie as credenciais abaixo e envie ao cliente com segurança.</p>
        <textarea id="copyDetails" class="copy-box" readonly></textarea>
        <button class="btn-primary" onclick="copyToClipboard()">📋 Copiar Credenciais</button>
    </div>
</div>

<script>
    function logout() {
        fetch('auth.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'action=logout'})
        .then(()=>window.location.href='login.html');
    }
    function openModal(id){document.getElementById(id).classList.add('active');}
    function closeModal(id){document.getElementById(id).classList.remove('active');}

    async function loadUsers(){
        const res=await fetch('auth.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'action=get_users'});
        const data=await res.json();
        const tbody=document.getElementById('usersList');
        tbody.innerHTML='';
        const now=Math.floor(Date.now()/1000);
        for(let uname in data.users){
            const u=data.users[uname];
            const isAdmin=u.role==='admin';
            const isInfinite=u.expiration===-1;
            const isExp=!isAdmin&&!isInfinite&&now>u.expiration;
            const createdDate=new Date(u.created_at*1000).toLocaleDateString('pt-BR');
            const expDate=(isAdmin||isInfinite)?'∞ Nunca':new Date(u.expiration*1000).toLocaleString('pt-BR');
            let bCls='badge role-badge ',bTxt='',bTip='';
            if(isAdmin){bCls+='badge-admin';bTxt='ADMIN';bTip=u.username==='admin'?'':'Clique para rebaixar';}
            else if(isExp){bCls+='badge-expired';bTxt='EXPIRADO';bTip='Clique para promover a admin';}
            else{bCls+='badge-success';bTxt='MEMBRO';bTip='Clique para promover a admin';}
            const isSuperAdmin=u.username==='admin';
            const badge=isSuperAdmin
                ?`<span class="${bCls}">${bTxt}</span>`
                :`<span class="${bCls}" title="${bTip}" onclick="toggleRole('${u.username}')">${bTxt}</span>`;
            let actions=`<button class="btn btn-sm" onclick="openEdit('${u.username}','${u.role}')">Editar</button>`;
            if(!isAdmin) actions+=`<button class="btn btn-sm btn-danger-sm" onclick="deleteUser('${u.username}')">Revogar</button>`;
            tbody.innerHTML+=`
            <tr>
                <td style="font-weight:600">${u.username}</td>
                <td>${badge}</td>
                <td style="color:var(--muted)">${createdDate}</td>
                <td style="color:${isExp?'var(--danger)':'var(--muted)'}">${expDate}</td>
                <td class="td-actions">${actions}</td>
            </tr>`;
        }
    }

    document.getElementById('createUserForm').addEventListener('submit',async(e)=>{
        e.preventDefault();
        const uname=document.getElementById('new_username').value;
        const pass=document.getElementById('new_password').value;
        const role=document.getElementById('new_role').value;
        const plan=document.getElementById('plan').value;
        const btn=e.target.querySelector('button[type="submit"]');
        btn.disabled=true;btn.textContent='Criando...';
        const fd=new URLSearchParams();
        fd.append('action','create_user');fd.append('new_username',uname);fd.append('new_password',pass);fd.append('plan',plan);fd.append('role',role);
        try{
            const res=await fetch('auth.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd});
            const data=await res.json();
            if(data.status==='success'){
                const createdDate=new Date().toLocaleDateString('pt-BR');
                const expLabel=data.expiration===-1?'∞ Sem expiração':new Date(data.expiration*1000).toLocaleString('pt-BR');
                const toolLink=window.location.origin+window.location.pathname.replace('admin.php','login.html');
                const roleLabel=data.role==='admin'?'Administrador':'Membro';
                const text=`🔥 Acesso Liberado: Kroenen Engine 🔥\n\n🔗 Link: ${toolLink}\n👤 Usuário: ${uname}\n🔑 Senha: ${pass}\n🛡️ Perfil: ${roleLabel}\n📅 Criado em: ${createdDate}\n⏳ Expira em: ${expLabel}`;
                document.getElementById('copyDetails').value=text;
                openModal('successModal');
                document.getElementById('createUserForm').reset();
                loadUsers();
            }else{alert('Erro: '+data.message);}
        }finally{btn.disabled=false;btn.textContent='Criar Conta';}
    });

    function openEdit(username,role){
        document.getElementById('editTargetUser').innerText=username;
        document.getElementById('edit_username').value=username;
        document.getElementById('edit_role').value=role;
        document.getElementById('edit_password').value='';
        document.getElementById('extend_days').value='0';
        document.getElementById('extendPlanGroup').style.display=role==='admin'?'none':'flex';
        openModal('editModal');
    }

    document.getElementById('editUserForm').addEventListener('submit',async(e)=>{
        e.preventDefault();
        const btn=e.target.querySelector('button[type="submit"]');
        btn.disabled=true;btn.textContent='Salvando...';
        const fd=new URLSearchParams();
        fd.append('action','edit_user');
        fd.append('edit_username',document.getElementById('edit_username').value);
        fd.append('new_password',document.getElementById('edit_password').value);
        fd.append('extend_days',document.getElementById('extend_days').value);
        try{
            const res=await fetch('auth.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd});
            const data=await res.json();
            if(data.status==='success'){closeModal('editModal');loadUsers();}
            else{alert('Erro: '+data.message);}
        }finally{btn.disabled=false;btn.textContent='Salvar Alterações';}
    });

    async function deleteUser(username){
        if(!confirm(`Revogar acesso de ${username}? Esta ação é irreversível.`))return;
        const fd=new URLSearchParams();fd.append('action','delete_user');fd.append('del_username',username);
        await fetch('auth.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd});
        loadUsers();
    }

    async function toggleRole(username){
        if(!confirm(`Alterar o papel de "${username}"? (admin ↔ membro)`))return;
        const fd=new URLSearchParams();fd.append('action','toggle_role');fd.append('target_username',username);
        const res=await fetch('auth.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd});
        const data=await res.json();
        if(data.status==='success')loadUsers();
        else alert('Erro: '+data.message);
    }

    function copyToClipboard(){
        const txt=document.getElementById('copyDetails');txt.select();document.execCommand('copy');
        alert('✅ Credenciais copiadas!');closeModal('successModal');
    }

    loadUsers();
</script>
</body>
</html>
