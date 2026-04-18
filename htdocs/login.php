<?php

declare(strict_types=1);

require_once __DIR__ . '/config/db.php';
require_once __DIR__ . '/config/helpers.php';
require_once __DIR__ . '/config/csrf.php';

session_start();

$errors = [];
$email = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_verify();

    $email = trim($_POST['email'] ?? '');
    $pass  = $_POST['password'] ?? '';

    if ($email === '' || $pass === '') {
        $errors[] = 'メールアドレスとパスワードを入力してください';
    } else {
        $pdo = db();
        $stmt = $pdo->prepare('SELECT id, name, password_hash FROM users WHERE email = :email');
        $stmt->execute([':email' => $email]);
        $user = $stmt->fetch();

        if ($user && password_verify($pass, $user['password_hash'])) {
            $_SESSION['user_id']   = (int)$user['id'];
            $_SESSION['user_name'] = $user['name'];

            header('Location: /');
            exit;
        } else {
            $errors[] = 'メールアドレスまたはパスワードが違います';
        }
    }
}
?>
<!doctype html>
<html lang="ja">

<head>
    <meta charset="utf-8">
    <title>ログイン | Drive Mapping</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: system-ui;
            margin: 20px;
        }

        form {
            max-width: 420px;
        }

        label {
            display: block;
            margin-top: 12px;
        }

        input {
            width: 100%;
            padding: 8px;
            margin-top: 4px;
        }

        button {
            margin-top: 16px;
            padding: 10px;
        }

        .error {
            color: #c00;
        }

        @media (max-width: 600px) {

            /* ✅ 全体を中央寄せにしない（流れを維持） */
            body {
                margin: 12px;          /* 画面端の余白だけ確保 */
            }

            h1 {
                text-align: center;
            }

            /* ✅ フォームの横幅をスマホに合わせて余白を作る */
            form {
                max-width: 420px;      /* 広がりすぎ防止 */
                margin: 0 auto;        /* “中央配置”ではなく“左右のバランス” */
                padding: 0 10px;       /* 入力欄が画面ギリギリにならない */
                box-sizing: border-box;
            }

            /* ✅ 横並びになってしまう場合の保険（formがflexなら縦に戻す） */
            form {
                display: block;
            }
            form * {
                max-width: 100%;
            }

            /* ✅ 入力欄：左右余白 + タップしやすい高さ */
            input[type="email"],
            input[type="password"],
            input[type="text"] {
                width: 100%;
                box-sizing: border-box;
                padding: 10px 12px;
            }

            /* ✅ ボタン：中央 + 少し長く */
            button,
            input[type="submit"] {
                display: block;
                width: 90%;
                margin: 14px auto 0;
                padding: 10px 12px;
            }

            /* ✅ 「新規登録」リンクが横に押し出されるのを防ぐ */
            a {
                word-break: break-word;
            }
        }
        
    </style>
</head>

<body>

    <h1>ログイン</h1>

    <?php if ($errors): ?>
        <ul class="error">
            <?php foreach ($errors as $e): ?><li><?= h($e) ?></li><?php endforeach; ?>
        </ul>
    <?php endif; ?>

    <form method="post">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token(), ENT_QUOTES, 'UTF-8') ?>">

        <label>
            メールアドレス
            <input type="email" name="email" value="<?= h($email) ?>">
        </label>

        <label>
            パスワード
            <input type="password" name="password">
        </label>

        <button type="submit">ログイン</button>
    </form>

    <p>アカウントをお持ちでない方は <a href="/register.php">新規登録</a></p>

</body>

</html>
