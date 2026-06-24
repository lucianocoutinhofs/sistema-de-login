from flask import Flask, render_template, request, redirect, session  # importa o flask e suas ferramentas
import sqlite3   # banco de dados
import bcrypt    # criptografia de senhas
import os        # manipular arquivos

app = Flask(__name__)           # cria o servidor flask
app.secret_key = "chave_secreta_123"  # chave para proteger a sessão do usuário

# ===== BANCO DE DADOS =====

def criar_banco():
    conexao = sqlite3.connect("usuarios.db")
    cursor = conexao.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            senha TEXT NOT NULL,
            tentativas INTEGER DEFAULT 0,
            bloqueado INTEGER DEFAULT 0
        )
    """)  # cria a tabela com todas as colunas
    conexao.commit()
    conexao.close()

def buscar_usuario(nome):
    conexao = sqlite3.connect("usuarios.db")
    cursor = conexao.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE nome = ?", (nome,))  # busca pelo nome
    usuario = cursor.fetchone()
    conexao.close()
    return usuario  # retorna os dados do usuário ou None

def cadastrar_usuario(nome, senha):
    conexao = sqlite3.connect("usuarios.db")
    cursor = conexao.cursor()
    if buscar_usuario(nome):  # se já existir
        return False, "Usuário já cadastrado!"
    senha_criptografada = bcrypt.hashpw(senha.encode(), bcrypt.gensalt())  # criptografa
    cursor.execute("INSERT INTO usuarios (nome, senha) VALUES (?, ?)", (nome, senha_criptografada))
    conexao.commit()
    conexao.close()
    return True, "Usuário cadastrado com sucesso!"

def atualizar_tentativas(id_usuario, tentativas, bloquear=False):
    conexao = sqlite3.connect("usuarios.db")
    cursor = conexao.cursor()
    cursor.execute(
        "UPDATE usuarios SET tentativas = ?, bloqueado = ? WHERE id = ?",
        (tentativas, 1 if bloquear else 0, id_usuario)
    )  # atualiza tentativas e status de bloqueio
    conexao.commit()
    conexao.close()

# ===== ROTAS =====

@app.route("/", methods=["GET", "POST"])  # página inicial — tela de login
def login():
    erro = None  # começa sem mensagem de erro

    if request.method == "POST":  # se o formulário foi enviado
        nome = request.form["nome"]    # pega o nome digitado
        senha = request.form["senha"]  # pega a senha digitada

        usuario = buscar_usuario(nome)  # busca no banco

        if not usuario:  # se não encontrou
            erro = "Usuário não encontrado!"
        else:
            id_usuario, nome_db, senha_db, tentativas, bloqueado = usuario  # separa os dados

            if bloqueado:  # se estiver bloqueado
                erro = "Usuário bloqueado após 3 tentativas erradas!"

            elif bcrypt.checkpw(senha.encode(), senha_db):  # se a senha estiver correta
                atualizar_tentativas(id_usuario, 0)  # zera as tentativas
                session["usuario"] = nome  # salva o usuário na sessão
                return redirect("/dashboard")  # redireciona para o dashboard

            else:  # senha errada
                tentativas += 1
                if tentativas >= 3:  # se errou 3 vezes
                    atualizar_tentativas(id_usuario, tentativas, bloquear=True)
                    erro = "Usuário bloqueado após 3 tentativas erradas!"
                else:
                    atualizar_tentativas(id_usuario, tentativas)
                    erro = f"Senha incorreta! Tentativa {tentativas}/3"

    return render_template("login.html", erro=erro)  # mostra a tela de login

@app.route("/cadastro", methods=["GET", "POST"])  # página de cadastro
def cadastro():
    mensagem = None
    sucesso = False

    if request.method == "POST":  # se o formulário foi enviado
        nome = request.form["nome"]
        senha = request.form["senha"]
        sucesso, mensagem = cadastrar_usuario(nome, senha)  # tenta cadastrar

    return render_template("cadastro.html", mensagem=mensagem, sucesso=sucesso)  # mostra a tela de cadastro

@app.route("/dashboard")  # página após o login
def dashboard():
    if "usuario" not in session:  # se não estiver logado
        return redirect("/")  # volta para o login
    return render_template("dashboard.html", nome=session["usuario"])  # mostra o dashboard

@app.route("/logout")  # rota para sair
def logout():
    session.clear()   # limpa a sessão
    return redirect("/")  # volta para o login

# ===== EXECUÇÃO =====

if os.path.exists("usuarios.db"):
    os.remove("usuarios.db")  # apaga banco antigo

criar_banco()  # cria banco novo

if __name__ == "__main__":
    app.run(debug=True)  # inicia o servidor em modo debug