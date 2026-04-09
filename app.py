from flask import Flask, render_template, request, redirect, url_for
import re
import sqlite3 # Mudamos de mysql.connector para sqlite3
import bcrypt

app = Flask(__name__)

# Agora não precisamos de IP ou Senha, apenas o nome do arquivo que você vai salvar
DB_FILE = "aguaviva123.db"

def get_db_connection():
    # Essa função abre o arquivo .db. Se ele não existir, o Python cria na hora.
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row # Isso faz o sqlite retornar dados igual ao MySQL (dictionary=True)
    return conn

# O restante das suas funções (EMAIL_RE, senha_forte) continua IGUAL...
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

def senha_forte(s: str) -> bool:
    if len(s) < 8: return False
    if not re.search(r"[A-Za-z]", s): return False
    if not re.search(r"\d", s): return False
    return True

@app.get("/")
def home():
    return render_template("index.html")

@app.get("/perfil")
def perfil():
    try:
        conn = get_db_connection()
        usuario = conn.execute("SELECT id, nome, email, cpf, endereco, estado, cidade FROM usuarios WHERE id = ?", (1,)).fetchone()
        conn.close()

        if not usuario:
            return "Usuario nao encontrado", 404
        
        return render_template("perfil.html", usuario=usuario)
    except Exception as e:
        return f"Erro no banco de dados: {e}", 500

@app.post("/register")
def register():
    # ... (seus gets do form continuam iguais)
    nome = (request.form.get("nome")).strip()
    email = (request.form.get("email")).strip()
    senha = (request.form.get("senha")).strip()
    cpf = (request.form.get("cpf", "")).strip()
    endereco = (request.form.get("endereco")).strip()
    estado = (request.form.get("estado")).strip()
    cidade = (request.form.get("cidade")).strip()

    # ... (suas validações continuam iguais)
    
    senha_hash = bcrypt.hashpw(senha.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    try:
        conn = get_db_connection()
        
        # No SQLite usamos '?' em vez de '%s'
        user_exists = conn.execute("SELECT id FROM usuarios WHERE email=?", (email, )).fetchone()
        if user_exists:
            conn.close()
            return "Esse email já esta cadastrado.", 400
        
        conn.execute(
            "INSERT INTO usuarios (nome, email, senha, cpf, endereco, estado, cidade) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (nome, email, senha_hash, cpf, endereco, estado, cidade)
        )
        conn.commit()
        conn.close()
        return redirect(url_for('home'))
    
    except Exception as e:
        return f"Erro ao salvar no arquivo .db: {e}", 500

if __name__ == "__main__":
    # SCRIPT PARA CRIAR A TABELA CASO ELA NÃO EXISTA
    # Isso garante que seu banco esteja pronto assim que você rodar o código
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT, email TEXT, senha TEXT, 
                cpf TEXT, endereco TEXT, estado TEXT, cidade TEXT
            )
        """)
    app.run(debug=True)