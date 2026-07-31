<?php
session_start();

$users_file = 'users.json';
if (!file_exists($users_file)) {
    die("Erro: users.json não encontrado.");
}
$users = json_decode(file_get_contents($users_file), true);

$action = $_POST['action'] ?? '';

if ($action === 'login') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    if (isset($users[$username]) && password_verify($password, $users[$username]['password'])) {
        $user = $users[$username];
        if (time() > $user['expiration'] && $user['expiration'] !== -1 && $user['role'] !== 'admin') {
            echo json_encode(['status' => 'error', 'message' => 'Plano expirado.']);
            exit;
        }
        
        $_SESSION['logged_in'] = true;
        $_SESSION['username'] = $username;
        $_SESSION['role'] = $user['role'];
        $_SESSION['expiration'] = $user['expiration'];
        
        echo json_encode(['status' => 'success', 'role' => $user['role']]);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Usuário ou senha inválidos.']);
    }
    exit;
}

if ($action === 'logout') {
    session_destroy();
    echo json_encode(['status' => 'success']);
    exit;
}

// Rotas de Admin
if (isset($_SESSION['logged_in']) && $_SESSION['role'] === 'admin') {
    if ($action === 'get_users') {
        echo json_encode(['status' => 'success', 'users' => $users]);
        exit;
    }
    
    if ($action === 'create_user') {
        $new_user = $_POST['new_username'] ?? '';
        $new_pass = $_POST['new_password'] ?? '';
        $plan  = $_POST['plan'] ?? '1'; // em dias; 0 = infinito
        $role  = $_POST['role'] ?? 'user'; // 'user' ou 'admin'
        if (!in_array($role, ['user', 'admin'])) $role = 'user';
        
        if (empty($new_user) || empty($new_pass)) {
            echo json_encode(['status' => 'error', 'message' => 'Preencha todos os campos.']);
            exit;
        }
        
        if (isset($users[$new_user])) {
            echo json_encode(['status' => 'error', 'message' => 'Usuário já existe.']);
            exit;
        }
        
        $days = (int)$plan;
        // -1 = nunca expira (admin ou plano infinito)
        if ($role === 'admin' || $days === 0) {
            $expiration = -1;
        } else {
            $expiration = time() + ($days * 24 * 60 * 60);
        }
        
        $users[$new_user] = [
            'username'   => $new_user,
            'password'   => password_hash($new_pass, PASSWORD_DEFAULT),
            'role'       => $role,
            'expiration' => $expiration,
            'created_at' => time()
        ];
        
        file_put_contents($users_file, json_encode($users, JSON_PRETTY_PRINT));
        echo json_encode(['status' => 'success', 'message' => 'Usuário criado com sucesso.', 'expiration' => $expiration, 'role' => $role]);
        exit;
    }
    
    if ($action === 'edit_user') {
        $edit_user = $_POST['edit_username'] ?? '';
        $new_pass = $_POST['new_password'] ?? '';
        $extend_days = (int)($_POST['extend_days'] ?? 0);
        
        if (!isset($users[$edit_user])) {
            echo json_encode(['status' => 'error', 'message' => 'Usuário não encontrado.']);
            exit;
        }
        
        // Atualizar Senha
        if (!empty($new_pass)) {
            $users[$edit_user]['password'] = password_hash($new_pass, PASSWORD_DEFAULT);
        }
        
        // Atualizar Assinatura (Dias) - Apenas se não for admin
        if ($extend_days > 0 && $users[$edit_user]['role'] !== 'admin') {
            $current_exp = $users[$edit_user]['expiration'];
            // Se já expirou, conta a partir de agora. Se não, soma no tempo restante.
            $base_time = ($current_exp > time()) ? $current_exp : time();
            $users[$edit_user]['expiration'] = $base_time + ($extend_days * 24 * 60 * 60);
        }
        
        file_put_contents($users_file, json_encode($users, JSON_PRETTY_PRINT));
        echo json_encode(['status' => 'success', 'message' => 'Usuário atualizado com sucesso.']);
        exit;
    }
    
    if ($action === 'delete_user') {
        $del_user = $_POST['del_username'] ?? '';
        if ($del_user === 'admin') {
            echo json_encode(['status' => 'error', 'message' => 'Não pode excluir o admin.']);
            exit;
        }
        if (isset($users[$del_user])) {
            unset($users[$del_user]);
            file_put_contents($users_file, json_encode($users, JSON_PRETTY_PRINT));
            echo json_encode(['status' => 'success']);
        } else {
            echo json_encode(['status' => 'error']);
        }
        exit;
    }

    if ($action === 'toggle_role') {
        $target = $_POST['target_username'] ?? '';
        if ($target === 'admin') {
            echo json_encode(['status' => 'error', 'message' => 'Não pode alterar o super admin.']);
            exit;
        }
        if (!isset($users[$target])) {
            echo json_encode(['status' => 'error', 'message' => 'Usuário não encontrado.']);
            exit;
        }
        $current_role = $users[$target]['role'];
        $new_role = ($current_role === 'admin') ? 'user' : 'admin';
        $users[$target]['role'] = $new_role;
        // Admins não expiram
        if ($new_role === 'admin') {
            $users[$target]['expiration'] = -1;
        }
        file_put_contents($users_file, json_encode($users, JSON_PRETTY_PRINT));
        echo json_encode(['status' => 'success', 'new_role' => $new_role]);
        exit;
    }
}

echo json_encode(['status' => 'error', 'message' => 'Acesso Negado']);
