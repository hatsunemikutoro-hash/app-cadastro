from flask import Flask, render_template, request, redirect, url_for, session
import re
import sqlite3
import bcrypt

app = Flask(__name__)
app.secret_key = "chave_secreta_senai"

DB_FILE = "aguaviva123.db"

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row  # Permite acessar colunas pelo nome: usuario['nome']
    return conn

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

def senha_forte(s: str) -> bool:
    if len(s) < 8: return False
    if not re.search(r"[A-Za-z]", s): return False
    if not re.search(r"\d", s): return False
    return True

@app.get("/")
def home():
    return render_template("index.html")

@app.get("/login")
def login_page():
    return render_template("login.html")

@app.post("/login")
def login():
    email = (request.form.get("email") or "").strip()
    senha = (request.form.get("senha") or "").strip()

    if not EMAIL_RE.match(email):
        return "Email inválido.", 400
    
    conn = get_db_connection()
    try:
        # CORREÇÃO: Usando '?' e get_db_connection em vez de mysql
        usuario = conn.execute(
            "SELECT id, nome, email, senha FROM usuarios WHERE email = ?",
            (email,)
        ).fetchone()

        if not usuario:
            return "Usuário não encontrado.", 404
        
        # O SQLite retorna bytes ou string dependendo da versão/config, 
        if not bcrypt.checkpw(senha.encode("utf-8"), usuario["senha"].encode("utf-8")):
            return "Senha incorreta.", 401

        # CORREÇÃO: Padronização da chave da session (usuario_id)
        session["usuario_id"] = usuario["id"]
        session["usuario_nome"] = usuario["nome"]
        return redirect(url_for("perfil"))
    except Exception as e:
        return f"Erro no banco de dados: {e}", 500
    finally:
        conn.close()

# ========= logout
@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))

@app.get("/edit_pg")
def editpg():
    if "usuario_id" not in session:
        return redirect(url_for("login_page"))
        
    conn = get_db_connection()
    usuario = conn.execute("SELECT * FROM usuarios WHERE id = ?", (session["usuario_id"],)).fetchone()
    conn.close()
    return render_template("edit.html", usuario=usuario)

# ========= perfil
@app.get("/perfil")
def perfil():
    # CORREÇÃO: A chave era 'usuario_id', não 'usuario.id'
    if "usuario_id" not in session:
        return redirect(url_for("login_page"))

    conn = get_db_connection()
    try:
        # CORREÇÃO: Usando '?' para SQLite
        usuario = conn.execute(
            "SELECT id, nome, email, cpf, endereco, estado, cidade FROM usuarios WHERE id = ?",
            (session["usuario_id"],)
        ).fetchone()

        if not usuario:
            session.clear()
            return redirect(url_for("login_page"))
        
        return render_template("perfil.html", usuario=usuario)
    except Exception as e:
        return f"Erro ao carregar perfil: {e}", 500
    finally:
        conn.close()
# ========= deletar
@app.post("/delete")
def delete():
    conn = get_db_connection()
    usuario_id = (request.form.get("id"))
    conn.execute("DELETE from usuarios where id = ?", (usuario_id, ))

    conn.commit()

    return render_template("index.html") # Volta para a página principal
    # DELETE from usuarios where id = %s

# ========= editar
# ========= editar
@app.post("/edit")
def edit():
    if "usuario_id" not in session:
        return redirect(url_for("login_page"))

    # 1. Pegar os dados que vieram do seu formulário HTML
    usuario_id = request.form.get("id")
    nome = request.form.get("nome")
    email = request.form.get("email")
    cpf = request.form.get("cpf")
    endereco = request.form.get("endereco")
    estado = request.form.get("estado")
    cidade = request.form.get("cidade")

    conn = get_db_connection()
    try:
        # 2. Executar o UPDATE
        conn.execute("""
            UPDATE usuarios 
            SET nome = ?, email = ?, cpf = ?, endereco = ?, estado = ?, cidade = ? 
            WHERE id = ?
        """, (nome, email, cpf, endereco, estado, cidade, usuario_id))
        
        conn.commit()
        
        # 3. Atualizar o nome na sessão caso ele tenha mudado
        session["usuario_nome"] = nome
        
        return redirect(url_for("perfil")) 
    except Exception as e:
        return f"Erro ao editar o perfil: {e}"
    finally:
        conn.close()

# ========= register
@app.post("/register")
def register():
    nome = (request.form.get("nome") or "").strip()
    email = (request.form.get("email") or "").strip()
    senha = (request.form.get("senha") or "").strip()
    cpf = (request.form.get("cpf") or "").strip()
    endereco = (request.form.get("endereco") or "").strip()
    estado = (request.form.get("estado") or "").strip()
    cidade = (request.form.get("cidade") or "").strip()

    if not all([nome, email, senha]):
        return "Preencha os campos obrigatórios.", 400

    senha_hash = bcrypt.hashpw(senha.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    conn = get_db_connection()
    try:
        user_exists = conn.execute("SELECT id FROM usuarios WHERE email=?", (email, )).fetchone()
        if user_exists:
            return "Esse email já está cadastrado.", 400
        
        conn.execute(
            "INSERT INTO usuarios (nome, email, senha, cpf, endereco, estado, cidade) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (nome, email, senha_hash, cpf, endereco, estado, cidade)
        )
        conn.commit()
        return redirect(url_for("login_page"))
    except Exception as e:
        return f"Erro ao salvar: {e}", 500
    finally:
        conn.close()

if __name__ == "__main__":
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT, email TEXT, senha TEXT, 
                cpf TEXT, endereco TEXT, estado TEXT, cidade TEXT
            )
        """)
    app.run(debug=True)