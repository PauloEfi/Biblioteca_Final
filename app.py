from datetime import date, timedelta
from functools import wraps
import os
from pathlib import Path
import sqlite3
from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

try:
    import mysql.connector as mysql_connector
    from mysql.connector import IntegrityError as MySQLIntegrityError
except ModuleNotFoundError:
    mysql_connector = None
    MySQLIntegrityError = ()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "bibliotech-dev-key")
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
app.jinja_env.auto_reload = True

ROLE_LABELS = {
    "admin": "Bibliotecário",
    "professor": "Professor",
    "aluno": "Aluno",
}

STATUS_LABELS = {
    "pendente": "Pendente",
    "aprovada": "Aprovada",
    "recusada": "Recusada",
}

@app.template_filter("status_label")
def status_label(value):
    return STATUS_LABELS.get(value, value)

LOAN_RULES = {
    "aluno": {"days": 7, "limit": 3},
    "professor": {"days": 15, "limit": 5},
}


def db_driver():
    return os.getenv("DB_DRIVER", "sqlite").strip().lower()


def db_config():
    return {
        "host": os.getenv("MYSQL_HOST", "localhost"),
        "port": int(os.getenv("MYSQL_PORT", "3306")),
        "user": os.getenv("MYSQL_USER", "root"),
        "password": os.getenv("MYSQL_PASSWORD", ""),
        "database": os.getenv("MYSQL_DATABASE", "bibliotech"),
    }


def sqlite_path():
    configured = os.getenv("SQLITE_DATABASE", "bibliotech.sqlite3")
    return Path(configured).resolve()


def prepare_sql(sql):
    if db_driver() != "sqlite":
        return sql
    return (
        sql.replace("%s", "?")
        .replace("CURDATE()", "DATE('now', 'localtime')")
        .replace("FOR UPDATE", "")
        .replace("LEAST(", "MIN(")
    )


def make_cursor(conn, dictionary=False):
    if db_driver() == "sqlite":
        return conn.cursor()
    return conn.cursor(dictionary=dictionary)


def row_to_dict(row):
    if row is None:
        return None
    if isinstance(row, dict):
        return row
    return dict(row)


def cursor_execute(cursor, sql, params=()):
    cursor.execute(prepare_sql(sql), params)


def cursor_fetchone(cursor):
    return row_to_dict(cursor.fetchone())


def begin_transaction(conn):
    if db_driver() == "sqlite":
        conn.execute("BEGIN IMMEDIATE")
    else:
        conn.start_transaction()


def initialize_sqlite(conn):
    schema = Path(__file__).with_name("schema_sqlite.sql")
    conn.executescript(schema.read_text(encoding="utf-8"))


def get_db():
    if "db" not in g:
        if db_driver() == "sqlite":
            conn = sqlite3.connect(sqlite_path(), isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            initialize_sqlite(conn)
            g.db = conn
        else:
            if mysql_connector is None:
                raise RuntimeError(
                    "mysql-connector-python não esta instalado. "
                    "Use DB_DRIVER=sqlite ou instale requirements.txt."
                )
            g.db = mysql_connector.connect(**db_config())
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is None:
        return
    if db_driver() == "sqlite":
        db.close()
    elif db.is_connected():
        db.close()


def fetch_one(sql, params=()):
    cursor = make_cursor(get_db(), dictionary=True)
    cursor_execute(cursor, sql, params)
    row = cursor_fetchone(cursor)
    cursor.close()
    return row


def fetch_all(sql, params=()):
    cursor = make_cursor(get_db(), dictionary=True)
    cursor_execute(cursor, sql, params)
    rows = [row_to_dict(row) for row in cursor.fetchall()]
    cursor.close()
    return rows


def execute(sql, params=()):
    conn = get_db()
    cursor = make_cursor(conn)
    cursor_execute(cursor, sql, params)
    conn.commit()
    last_id = cursor.lastrowid
    cursor.close()
    return last_id


INTEGRITY_ERRORS = (sqlite3.IntegrityError,) + (
    (MySQLIntegrityError,) if mysql_connector is not None else ()
)
DATABASE_ERRORS = (sqlite3.Error,) + (
    (mysql_connector.Error,) if mysql_connector is not None else ()
)


def scalar(sql, params=()):
    row = fetch_one(sql, params)
    return next(iter(row.values())) if row else 0


@app.before_request
def load_logged_user():
    g.user = None
    user_id = session.get("user_id")
    if user_id:
        g.user = fetch_one(
            "SELECT id, name, email, role, active FROM users WHERE id = %s AND active = TRUE",
            (user_id,),
        )
        if g.user is None:
            session.clear()


from datetime import datetime

@app.template_filter("brdate")
def brdate(value):
    if not value:
        return "-"

    if hasattr(value, "strftime"):
        return value.strftime("%d/%m/%Y")

    try:
        return datetime.fromisoformat(str(value)).strftime("%d/%m/%Y")
    except ValueError:
        try:
            return datetime.strptime(str(value), "%Y-%m-%d").strftime("%d/%m/%Y")
        except ValueError:
            return str(value)


@app.template_filter("role_label")
def role_label(value):
    return ROLE_LABELS.get(value, value)


@app.context_processor
def inject_globals():
    return {"roles": ROLE_LABELS, "today": date.today()}


@app.after_request
def disable_cache(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash("Faça login para acessar esta área.", "warning")
            return redirect(url_for("login"))
        return view(**kwargs)

    return wrapped_view


def roles_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped_view(**kwargs):
            if g.user is None:
                flash("Faça login para acessar esta área.", "warning")
                return redirect(url_for("login"))
            if g.user["role"] not in roles:
                flash("Você não tem permissão para acessar esta área.", "danger")
                return redirect(url_for("painel"))
            return view(**kwargs)

        return wrapped_view

    return decorator


def redirect_by_role(role):
    return redirect(url_for("catalogo"))


def required_fields(form, names):
    errors = []
    for field, label in names:
        if not form.get(field, "").strip():
            errors.append(f"{label} é obrigatório.")
    return errors


def parse_non_negative_int(raw_value, label, errors):
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        errors.append(f"{label} deve ser um número inteiro.")
        return 0
    if value < 0:
        errors.append(f"{label} não pode ser negativo.")
    return value


def formulario_livro_data():
    form = request.form
    errors = required_fields(
        form,
        [
            ("isbn", "ISBN - 13"),
            ("title", "Título"),
            ("authors", "Autores"),
            ("category", "Categoria"),
            ("publisher", "Editora"),
            ("publication_year", "Ano"),
            ("total_copies", "Total de exemplares"),
        ],
    )
    
    isbn = form.get("isbn", "").strip()
    
    if isbn:
        if len(isbn) > 13:
            errors.append("O ISBN deve ter no máximo 13 dígitos.")
        for caractere in isbn:
            if not (caractere.isdigit() or caractere == "-"):
                errors.append("O ISBN deve conter apenas números e hífens. Letras ou outros símbolos não são permitidos.")
                break 

    year = parse_non_negative_int(form.get("publication_year"), "Ano", errors)
    total = parse_non_negative_int(form.get("total_copies"), "Total de exemplares", errors)
    
    data = {
        "isbn": isbn,
        "title": form.get("title", "").strip(),
        "authors": form.get("authors", "").strip(),
        "category": form.get("category", "").strip(),
        "publisher": form.get("publisher", "").strip(),
        "publication_year": year,
        "total_copies": total,
    }
    return data, errors


@app.route("/")
def catalogo():
    q = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    params = []
    where = ["is_active = TRUE"]

    if q:
        where.append("(title LIKE %s OR authors LIKE %s OR isbn LIKE %s)")
        like = f"%{q}%"
        params.extend([like, like, like])
    if category:
        where.append("category = %s")
        params.append(category)

    books = fetch_all(
        f"""
        SELECT id, isbn, title, authors, category, publisher, publication_year,
               total_copies, available_copies
        FROM books
        WHERE {' AND '.join(where)}
        ORDER BY title
        """,
        tuple(params),
    )
    categories = fetch_all(
        "SELECT DISTINCT category FROM books WHERE is_active = TRUE ORDER BY category"
    )
    return render_template(
        "catalogo.html",
        books=books,
        categories=categories,
        q=q,
        selected_category=category,
    )


@app.route("/livros/<int:book_id>")
def detalhe_livro(book_id):
    book = fetch_one(
        """
        SELECT id, isbn, title, authors, category, publisher, publication_year,
               total_copies, available_copies
        FROM books
        WHERE id = %s AND is_active = TRUE
        """,
        (book_id,),
    )
    if book is None:
        flash("Livro não encontrado.", "warning")
        return redirect(url_for("catalogo"))
    return render_template("detalhe_livro.html", book=book)


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect_by_role(g.user["role"])

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = fetch_one(
            "SELECT id, name, email, password_hash, role, active FROM users WHERE email = %s",
            (email,),
        )

        if user and user["active"] and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            flash("Login realizado com sucesso.", "success")
            return redirect_by_role(user["role"])

        flash("E-mail ou senhá inválidos.", "danger")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Sessão encerrada.", "info")
    return redirect(url_for("catalogo"))


@app.route("/painel")
@login_required
def painel():
    if g.user["role"] == "admin":
        return redirect(url_for("admin_inicio"))

    loans = fetch_all(
        """
        SELECT l.id, l.loan_date, l.due_date, l.returned_at,
               b.title, b.authors, b.category,
               CASE WHEN l.returned_at IS NULL AND l.due_date < CURDATE()
                    THEN TRUE ELSE FALSE END AS is_overdue
        FROM loans l
        JOIN books b ON b.id = l.book_id
        WHERE l.user_id = %s
        ORDER BY l.returned_at IS NULL DESC, l.due_date ASC, l.loan_date DESC
        """,
        (g.user["id"],),
    )
    requests = []
    if g.user["role"] == "professor":
        requests = fetch_all(
            """
            SELECT id, title, authors, category, publisher, status, created_at
            FROM acquisition_requests
            WHERE user_id = %s
            ORDER BY created_at DESC
            """,
            (g.user["id"],),
        )
    return render_template("painel.html", loans=loans, requests=requests)


@app.route("/admin")
@roles_required("admin")
def admin_inicio():
    stats = {
        "users": scalar("SELECT COUNT(*) AS value FROM users WHERE active = TRUE"),
        "books": scalar("SELECT COUNT(*) AS value FROM books WHERE is_active = TRUE"),
        "active_loans": scalar("SELECT COUNT(*) AS value FROM loans WHERE returned_at IS NULL"),
        "overdue_users": scalar(
            """
            SELECT COUNT(DISTINCT user_id) AS value
            FROM loans
            WHERE returned_at IS NULL AND due_date < CURDATE()
            """
        ),
    }
    recent_loans = fetch_all(
        """
        SELECT l.id, l.loan_date, l.due_date, l.returned_at,
               u.name AS user_name, u.role, b.title AS book_title
        FROM loans l
        JOIN users u ON u.id = l.user_id
        JOIN books b ON b.id = l.book_id
        ORDER BY l.created_at DESC
        LIMIT 8
        """
    )
    return render_template("admin_inicio.html", stats=stats, recent_loans=recent_loans)


@app.route("/admin/usuarios")
@roles_required("admin")
def admin_usuarios():
    users = fetch_all(
        """
        SELECT id, name, email, role, active, created_at
        FROM users
        ORDER BY role, name
        """
    )
    return render_template("admin_usuarios.html", users=users)


@app.route("/admin/usuarios/novo", methods=["GET", "POST"])
@roles_required("admin")
def create_user():
    if request.method == "POST":
        errors = required_fields(
            request.form,
            [
                ("name", "Nome"),
                ("email", "E-mail"),
                ("password", "Senha"),
                ("role", "Perfil"),
            ],
        )
        role = request.form.get("role", "")
        if role not in ROLE_LABELS:
            errors.append("Perfil inválido.")
        if request.form.get("password") and len(request.form["password"]) < 6:
            errors.append("A senhá deve ter pelo menos 6 caracteres.")

        if not errors:
            try:
                execute(
                    """
                    INSERT INTO users (name, email, password_hash, role)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (
                        request.form["name"].strip(),
                        request.form["email"].strip().lower(),
                        generate_password_hash(request.form["password"]),
                        role,
                    ),
                )
                flash("Usuário cadastrado com sucesso.", "success")
                return redirect(url_for("admin_usuarios"))
            except INTEGRITY_ERRORS:
                errors.append("Já existe um usuario com este e-mail.")

        for error in errors:
            flash(error, "danger")

    return render_template("formulario_usuario.html")
@app.route("/admin/usuarios/<int:user_id>/excluir", methods=["POST"])

@roles_required("admin")
def delete_user(user_id):
   
    if user_id == g.user["id"]:
        flash("Você não pode excluir sua própria conta.", "danger")
        return redirect(url_for("admin_usuarios"))

   
    user = fetch_one(
        "SELECT id, name FROM users WHERE id = %s",
        (user_id,),
    )

    if user is None:
        flash("Usuário não encontrado.", "warning")
        return redirect(url_for("admin_usuarios"))

   
    active_loans = scalar(
        """
        SELECT COUNT(*) AS value
        FROM loans
        WHERE user_id = %s
          AND returned_at IS NULL
        """,
        (user_id,),
    )

    if active_loans > 0:
        flash(
            "Não é possível excluir um usuário com empréstimos ativos.",
            "danger",
        )
        return redirect(url_for("admin_usuarios"))

    try:
       
        execute(
            "DELETE FROM loans WHERE user_id = %s",
            (user_id,),
        )

       
        execute(
            "DELETE FROM acquisition_requests WHERE user_id = %s",
            (user_id,),
        )

       
        execute(
            "DELETE FROM users WHERE id = %s",
            (user_id,),
        )

        flash("Usuário excluído com sucesso.", "success")

    except DATABASE_ERRORS as exc:
        flash(f"Erro ao excluir usuário: {exc}", "danger")

    return redirect(url_for("admin_usuarios"))


@app.route("/admin/livros")
@roles_required("admin")
def admin_livros():
    books = fetch_all(
        """
        SELECT id, isbn, title, authors, category, publisher, publication_year,
               total_copies, available_copies
        FROM books
        WHERE is_active = TRUE
        ORDER BY title
        """
    )
    return render_template("admin_livros.html", books=books)

@app.route("/admin/emprestimos/<int:loans_id>/prazo", methods=["POST"])
@roles_required("admin")
def mudar_prazo(loans_id):
    nova_data = request.form.get("nova_data")
    
    if not nova_data:
        flash("Por favor, selecione uma data válida.", "danger")
        return redirect(url_for("admin_emprestimos"))

    try:
       
        execute(
            """
            UPDATE loans
            SET due_date = %s
            WHERE id = %s
            """,
            (nova_data, loans_id),
        )
        flash("Prazo de devolução alterado com sucesso!", "success")
    except DATABASE_ERRORS as exc:
        flash(f"Erro ao alterar o prazo: {exc}", "danger")

    return redirect(url_for("admin_emprestimos"))

@app.route("/admin/livros/novo", methods=["GET", "POST"])
@roles_required("admin")
def new_book():
    if request.method == "POST":
        data, errors = formulario_livro_data()
        if not errors:
            try:
                execute(
                    """
                    INSERT INTO books
                      (isbn, title, authors, category, publisher,
                       publication_year, total_copies, available_copies)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        data["isbn"],
                        data["title"],
                        data["authors"],
                        data["category"],
                        data["publisher"],
                        data["publication_year"],
                        data["total_copies"],
                        data["total_copies"],
                    ),
                )
                flash("Livro cadastrado com sucesso.", "success")
                return redirect(url_for("admin_livros"))
            except INTEGRITY_ERRORS:
                errors.append("Já existe um livro cadastrado com este ISBN.")

        for error in errors:
            flash(error, "danger")

    return render_template("formulario_livro.html", book=None)


@app.route("/admin/livros/<int:book_id>/editar", methods=["GET", "POST"])
@roles_required("admin")
def edit_book(book_id):
    book = fetch_one("SELECT * FROM books WHERE id = %s AND is_active = TRUE", (book_id,))
    if book is None:
        flash("Livro não encontrado.", "warning")
        return redirect(url_for("admin_livros"))

    active_loans = scalar(
        "SELECT COUNT(*) AS value FROM loans WHERE book_id = %s AND returned_at IS NULL",
        (book_id,),
    )

    if request.method == "POST":
        data, errors = formulario_livro_data()
        if data["total_copies"] < active_loans:
            errors.append(
                "Total de exemplares não pode ser menor que a quantidade emprestada."
            )

        if not errors:
            try:
                available = data["total_copies"] - active_loans
                execute(
                    """
                    UPDATE books
                    SET isbn = %s, title = %s, authors = %s, category = %s,
                        publisher = %s, publication_year = %s,
                        total_copies = %s, available_copies = %s
                    WHERE id = %s
                    """,
                    (
                        data["isbn"],
                        data["title"],
                        data["authors"],
                        data["category"],
                        data["publisher"],
                        data["publication_year"],
                        data["total_copies"],
                        available,
                        book_id,
                    ),
                )
                flash("Livro atualizado com sucesso.", "success")
                return redirect(url_for("admin_livros"))
            except INTEGRITY_ERRORS:
                errors.append("Já existe outro livro com este ISBN.")

        for error in errors:
            flash(error, "danger")
        book.update(data)

    return render_template("formulario_livro.html", book=book, active_loans=active_loans)


@app.route("/admin/livros/<int:book_id>/excluir", methods=["POST"])
@roles_required("admin")
def delete_book(book_id):
    active_loans = scalar(
        "SELECT COUNT(*) AS value FROM loans WHERE book_id = %s AND returned_at IS NULL",
        (book_id,),
    )
    if active_loans:
        flash("Nao é possível excluir livro com empréstimo ativo.", "danger")
        return redirect(url_for("admin_livros"))

    execute("UPDATE books SET is_active = FALSE WHERE id = %s", (book_id,))
    flash("Livro removido do acervo.", "info")
    return redirect(url_for("admin_livros"))


@app.route("/admin/empréstimos")
@roles_required("admin")
def admin_emprestimos():
    active_loans = fetch_all(
        """
        SELECT l.id, l.loan_date, l.due_date,
               u.name AS user_name, u.role, b.title AS book_title,
               CASE WHEN l.due_date < CURDATE() THEN TRUE ELSE FALSE END AS is_overdue
        FROM loans l
        JOIN users u ON u.id = l.user_id
        JOIN books b ON b.id = l.book_id
        WHERE l.returned_at IS NULL
        ORDER BY l.due_date ASC
        """
    )
    returned_loans = fetch_all(
        """
        SELECT l.id, l.loan_date, l.due_date, l.returned_at,
               u.name AS user_name, u.role, b.title AS book_title
        FROM loans l
        JOIN users u ON u.id = l.user_id
        JOIN books b ON b.id = l.book_id
        WHERE l.returned_at IS NOT NULL
        ORDER BY l.returned_at DESC
        LIMIT 25
        """
    )
    return render_template(
        "admin_emprestimos.html",
        active_loans=active_loans,
        returned_loans=returned_loans,
        loans=active_loans,
        emprestimos=active_loans     
    )


@app.route("/admin/empréstimos/novo", methods=["GET", "POST"])
@roles_required("admin")
def new_loan():
    if request.method == "POST":
        user_id = request.form.get("user_id")
        book_id = request.form.get("book_id")
        conn = get_db()
        cursor = make_cursor(conn, dictionary=True)
        try:
            begin_transaction(conn)
            cursor_execute(
                cursor,
                "SELECT id, name, role FROM users WHERE id = %s AND active = TRUE FOR UPDATE",
                (user_id,),
            )
            user = cursor_fetchone(cursor)
            cursor_execute(
                cursor,
                """
                SELECT id, title, available_copies
                FROM books
                WHERE id = %s AND is_active = TRUE
                FOR UPDATE
                """,
                (book_id,),
            )
            book = cursor_fetchone(cursor)

            errors = []
            if not user or user["role"] not in LOAN_RULES:
                errors.append("Selecione um aluno ou professor valido.")
            if not book:
                errors.append("Selecione um livro valido.")
            elif book["available_copies"] <= 0:
                errors.append("Nao há exemplares disponíveis deste livro.")

            if not errors and user:
                cursor_execute(
                    cursor,
                    """
                    SELECT COUNT(*) AS total
                    FROM loans
                    WHERE user_id = %s AND returned_at IS NULL
                    """,
                    (user["id"],),
                )
                active_total = cursor_fetchone(cursor)["total"]
                limit = LOAN_RULES[user["role"]]["limit"]
                if active_total >= limit:
                    errors.append(
                        f"{ROLE_LABELS[user['role']]} atingiu o limite de {limit} livros."
                    )

            if errors:
                conn.rollback()
                for error in errors:
                    flash(error, "danger")
                return redirect(url_for("new_loan"))

            rules = LOAN_RULES[user["role"]]
            loan_date = date.today()
            due_date = loan_date + timedelta(days=rules["days"])
            cursor_execute(
                cursor,
                """
                INSERT INTO loans (user_id, book_id, loan_date, due_date)
                VALUES (%s, %s, %s, %s)
                """,
                (user["id"], book["id"], loan_date, due_date),
            )
            cursor_execute(
                cursor,
                """
                UPDATE books
                SET available_copies = available_copies - 1
                WHERE id = %s
                """,
                (book["id"],),
            )
            conn.commit()
            flash("Empréstimo registrado com sucesso.", "success")
            return redirect(url_for("admin_emprestimos"))
        except DATABASE_ERRORS as exc:
            conn.rollback()
            flash(f"Erro ao registrar empréstimo: {exc}", "danger")
        finally:
            cursor.close()

    users = fetch_all(
        """
        SELECT id, name, email, role
        FROM users
        WHERE active = TRUE AND role IN ('aluno', 'professor')
        ORDER BY role, name
        """
    )
    books = fetch_all(
        """
        SELECT id, title, authors, available_copies
        FROM books
        WHERE is_active = TRUE AND available_copies > 0
        ORDER BY title
        """
    )
    return render_template("formulario_emprestimo.html", users=users, books=books)


@app.route("/admin/empréstimos/<int:loan_id>/devolver", methods=["POST"])
@roles_required("admin")
def return_loan(loan_id):
    conn = get_db()
    cursor = make_cursor(conn, dictionary=True)
    try:
        begin_transaction(conn)
        cursor_execute(
            cursor,
            """
            SELECT id, book_id
            FROM loans
            WHERE id = %s AND returned_at IS NULL
            FOR UPDATE
            """,
            (loan_id,),
        )
        loan = cursor_fetchone(cursor)
        if loan is None:
            conn.rollback()
            flash("Empréstimo ativo não encontrado.", "warning")
            return redirect(url_for("admin_emprestimos"))

        cursor_execute(
            cursor,
            "UPDATE loans SET returned_at = %s WHERE id = %s",
            (date.today(), loan_id),
        )
        cursor_execute(
            cursor,
            """
            UPDATE books
            SET available_copies = LEAST(available_copies + 1, total_copies)
            WHERE id = %s
            """,
            (loan["book_id"],),
        )
        conn.commit()
        flash("Devolução registrada com sucesso.", "success")
    except DATABASE_ERRORS as exc:
        conn.rollback()
        flash(f"Erro ao registrar devolução: {exc}", "danger")
    finally:
        cursor.close()
    return redirect(url_for("admin_emprestimos"))


@app.route("/solicitacoes/nova", methods=["GET", "POST"])
@roles_required("professor")
def new_acquisition_request():
    if request.method == "POST":
        errors = required_fields(
            request.form,
            [
                ("title", "Título"),
                ("authors", "Autores"),
                ("category", "Categoria"),
            ],
        )
        if not errors:
            execute(
                """
                INSERT INTO acquisition_requests
                  (user_id, title, authors, category, publisher, justification)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    g.user["id"],
                    request.form["title"].strip(),
                    request.form["authors"].strip(),
                    request.form["category"].strip(),
                    request.form.get("publisher", "").strip() or None,
                    request.form.get("justification", "").strip() or None,
                ),
            )
            flash("Solicitação enviada ao bibliotecário.", "success")
            return redirect(url_for("painel"))

        for error in errors:
            flash(error, "danger")

    return render_template("formulario_solicitacao.html")


@app.route("/admin/solicitacoes")
@roles_required("admin")
def admin_solicitacoes():
    requests_ = fetch_all(
        """
        SELECT ar.id, ar.title, ar.authors, ar.category, ar.publisher,
               ar.justification, ar.status, ar.created_at, ar.reviewed_at,
               u.name AS user_name, u.email AS user_email
        FROM acquisition_requests ar
        JOIN users u ON u.id = ar.user_id
        ORDER BY ar.status = 'pendente' DESC, ar.created_at DESC
        """
    )
    return render_template("admin_solicitacoes.html", requests=requests_)


@app.route("/admin/solicitacoes/<int:request_id>/status", methods=["POST"])
@roles_required("admin")
def update_request_status(request_id):
    status = request.form.get("status")
    if status not in {"pendente", "aprovada", "recusada"}:
        flash("Status inválido.", "danger")
        return redirect(url_for("admin_solicitacoes"))

    execute(
        """
        UPDATE acquisition_requests
        SET status = %s, reviewed_at = CURRENT_TIMESTAMP
        WHERE id = %s
        """,
        (status, request_id),
    )
    flash("Solicitação atualizada.", "success")
    return redirect(url_for("admin_solicitacoes"))


@app.route("/admin/relatorios")
@roles_required("admin")
def relatorio():
    days_late_expr = "DATEDIFF(CURDATE(), l.due_date)"
    if db_driver() == "sqlite":
        days_late_expr = (
            "CAST(julianday(DATE('now', 'localtime')) - julianday(l.due_date) AS INTEGER)"
        )
    category_stats = fetch_all(
        """
        SELECT category,
               COUNT(*) AS book_records,
               SUM(total_copies) AS total_copies,
               SUM(available_copies) AS available_copies
        FROM books
        WHERE is_active = TRUE
        GROUP BY category
        ORDER BY category
        """
    )
    active_total = scalar("SELECT COUNT(*) AS value FROM loans WHERE returned_at IS NULL")
    overdue = fetch_all(
        f"""
        SELECT u.id AS user_id, u.name AS user_name, u.email, u.role,
               b.title AS book_title, l.due_date,
               {days_late_expr} AS days_late
        FROM loans l
        JOIN users u ON u.id = l.user_id
        JOIN books b ON b.id = l.book_id
        WHERE l.returned_at IS NULL AND l.due_date < CURDATE()
        ORDER BY l.due_date ASC, u.name
        """
    )
    return render_template(
        "relatorio.html",
        category_stats=category_stats,
        active_total=active_total,
        overdue=overdue,
    )


@app.errorhandler(sqlite3.Error)
def database_error(error):
    return render_template("db_error.html", error=error), 500


if mysql_connector is not None:
    app.register_error_handler(mysql_connector.Error, database_error)


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "1") == "1")
