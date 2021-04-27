from flask import Flask, flash, redirect, render_template, request, session, url_for, jsonify
from flask_session import Session
from flask_mail import Mail, Message
from werkzeug.security import check_password_hash, generate_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from aditional import generate_confirmation_token, confirm_token, login_required
from tempfile import mkdtemp
from datetime import datetime
import markdown
import sqlite3

app = Flask(__name__)

app.config.from_pyfile('config.cfg')

mail = Mail(app)
app.config["TEMPLATES_AUTO_RELOAD"] = True
# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
#salt layer in the decoder
app.config["SECURITY_PASSWORD_SALT"] = "saltysalty"
app.config['SECRET_KEY'] = "skey"
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
# setting the connection with the database
database = sqlite3.connect("C:/Users/Piotr/Desktop/Documentation Generator/data.db", check_same_thread=False)
db = database.cursor()
print("Successfully Connected to SQLite")

@app.route("/", methods=['GET', 'POST'])
@login_required
def index():
    return redirect("/my-documentations")

@app.route("/my-documentations", methods=['GET', 'POST'])
@login_required
def my_documentations():
    if request.method == "POST":
        if(request.form['mode'] == 'redirect'):
            output = db.execute("SELECT * FROM doc_master WHERE id = ?", [request.form['value']]).fetchall()
            readme = markdown.markdown(output[0][4])
            return render_template("/documentation-page.html", out=output[0], readme=readme)
        elif(request.form['mode'] == 'delete'):
            x = request.form['value']
            db.execute("DELETE FROM doc_master WHERE id = ?", [x])
            database.commit()
            return jsonify({'success': "deleted"})
    output = db.execute("SELECT * FROM doc_master WHERE userID = ?", [session['user_id']]).fetchall()
    if(len(output) == 0):
        return render_template("/my-documentations.html", first=True)
    else:
        return render_template("/my-documentations.html", first=False, output=output)

@app.route("/add-documentation", methods=['GET', 'POST'])
@login_required
def add_doc():
    if request.method == "POST":
        x = request.form['title']
        readme = request.form['readme']
        code = request.form['code']
        discription = request.form['discription']
        if x == "" or readme == "" or code == "" or discription == "":
            return jsonify({'error': "missing"})
        else:
            data = (session["user_id"],
                x, 
                discription, 
                readme, 
                code)
            db.execute("INSERT INTO doc_master (userID, title, discription, readme, content) VALUES(?,?,?,?,?)", data)
            database.commit()
        return redirect("/")
    return render_template("add-documentation.html")

@app.route("/confirm", methods=['GET', 'POST'])
@login_required
def confirm():
    if request.method == "POST":
        if request.form.get("submit"):
            return redirect("/login")
    return render_template("confirm.html", email=session["email"])

@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect("/")

@app.route("/send-confirmation-mail", methods=['GET', 'POST'])
@login_required
def send_confirmation_mail():
    token = generate_confirmation_token(app, session['email'])
    msg = Message('Confirm Email', sender='noreplay@middle-europe-production.net', recipients=[session['email']])
    link = url_for('confirm', _external=True)
    link = link + "/" + token
    msg.html = render_template("email_template.html", name=session["firstname"], link=link)
    mail.send(msg)
    return "email send"

@app.route("/confirm/<token>", methods=['GET'])
@login_required
def confirm_page(token):
    try:
        email = confirm_token(app, token)
    except:
        return render_template("confirmed.html", success=False, msg="COULD NOT VERIFY")
    if session["email"] != email:
        return render_template("confirmed.html", success=False, msg="COULD NOT VERIFY")
    else:
        if session["confirmed"] == True:
            return render_template("confirmed.html", success=True)
        now = datetime.now()
        data = (now.strftime("%d-%m-%Y %H:%M:%S"), session["user_id"])
        db.execute("UPDATE users SET verification_date = ? WHERE id = ?", data)
        database.commit()

        session["confirmed"] = True
    return render_template("confirmed.html", success=True)

@app.route("/login-page", methods=["GET", "POST"])
def login():
    #forget_user_id--------------------------------------
    session.clear()

    if request.method == "POST":
        #------------------------------------------------
        if not request.form.get("login"):
           return render_template("login-page.html", statement = True, msg = "Missing field!")
        if not request.form.get("password"):
            return render_template("login-page.html", statement = True, msg = "Missing field!")
        #errors------------------------------------------
        out = db.execute("SELECT * FROM users WHERE username = ?", [request.form.get("login")]).fetchall()
        if len(out) == 0:
            return render_template("login-page.html", statement = True, msg = "Invalid Username or Password!")
        if check_password_hash(out[0][4], request.form.get("password")) == False:
            return render_template("login-page.html", statement = True, msg = "Invalid Username or Password!")
        #updating the session
        session["user_id"] = out[0][0]
        session["firstname"] = out[0][1]
        session["email"] = out[0][5]
        if out[0][7] is None:
            session["confirmed"] = False
            return redirect("/confirm")
        session["confirmed"] = True
        return redirect("/")
    return render_template("login-page.html", statement = False, msg = "")

@app.route("/register-page", methods=["GET", "POST"])
def register():
    #forget_user_id--------------------------------------
    session.clear()
    if request.method == "POST":
        #errors------------------------------------------
        if not request.form.get("firstname"):
            return render_template("register-page.html", statement = True, msg="Missing First Name!")
        if not request.form.get("secondname"):
            return render_template("register-page.html", statement = True, msg="Missing Second Name!")
        if not request.form.get("username"):
            return render_template("register-page.html", statement = True, msg="Missing Username!")
        if not request.form.get("password"):
            return render_template("register-page.html", statement = True, msg="Missing Password!")
        if not request.form.get("repeat"):
            return render_template("register-page.html", statement = True, msg="You did not repeat the password!")
        if not request.form.get("email"):
            return render_template("register-page.html", statement = True, msg="Missing Email!")
        if request.form.get("password") != request.form.get("repeat"):
            return render_template("register-page.html", statement = True, msg="Passwords does not match!")
        #errors------------------------------------------
        check = db.execute("SELECT * FROM users WHERE username = ?", [request.form.get("username")]).fetchall()
        if len(check) != 0:
            return render_template("register-page.html", statement = True, msg="This username already exists!")
        check2 = db.execute("SELECT * FROM users WHERE email = ?", [request.form.get("email")]).fetchall()
        if len(check2) != 0:
            return render_template("register-page.html", statement = True, msg="This email was already used!")
        #dbchecks----------------------------------------
        hash_password = generate_password_hash(request.form.get("password"))
        now = datetime.now()
        #inserting to the database
        data = (request.form.get("firstname"), 
                request.form.get("secondname"), 
                request.form.get("username"), 
                hash_password, 
                request.form.get("email"), 
                now.strftime("%d-%m-%Y %H:%M:%S"))
        db.execute("INSERT INTO users (firstname, secondname, username, hash, email, creation_date) VALUES(?, ?, ?, ?, ?, ?)",
                    data)
        database.commit()
        #update session
        session["user_id"] = db.lastrowid
        session["firstname"] = request.form.get("firstname")
        session["email"] = request.form.get("email")
        session["confirmed"] = False
        #sending a confirmation email
        token = generate_confirmation_token(app, session['email'])
        msg = Message('Confirm Email', sender='noreplay@middle-europe-production.net', recipients=[session['email']])
        link = url_for('confirm', _external=True)
        link = link + "/" + token
        msg.html = render_template("email_template.html", name=session["firstname"], link=link)
        mail.send(msg)
        
        return redirect("/confirm")
    return render_template("register-page.html", statement = False, msg="")

if __name__ == "__main__":
    app.run()
    db.close()