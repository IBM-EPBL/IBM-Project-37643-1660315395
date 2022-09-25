from flask import Flask, render_template, request, redirect, url_for
import ibm_db

app = Flask(__name__)

try:
    conn = ibm_db.connect("DATABASE=bludb;HOSTNAME=125f9f61-9715-46f9-9399-c8177b21803b.c1ogj3sd0tgtu0lqde00.databases.appdomain.cloud;PORT=30426;SECURITY=SSL;SSLServerCertificate=DigiCertGlobalRootCA.crt;PROTOCOL=TCPIP;UID=ynk41023;PWD=i7hvrcTXZSl8lDRI;", "", "")
    print("connected")
except:
    print("failed")

def insert_values(conn, email, username, rollno, pwd):
    sql = "INSERT into user values ('{}', '{}','{}', '{}')".format(email, username, rollno, pwd)
    stmt = ibm_db.exec_immediate(conn, sql)
    print("Number of affected rows: ", ibm_db.num_rows(stmt))

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/signin")
def render_signin(accountok=True):
    if accountok == True:
        return render_template("signin.html", message = "")
    else:
        return render_template("signin.html", message = "Username/Password is wrong")

@app.route("/login", methods = ['POST', 'GET'])
def checkLogin():
    if request.method == 'POST':
        mail = request.form['email']
        pwd = request.form['password']
        sql = "SELECT * from user where email = '{}'".format(mail)
        
        stmt = ibm_db.exec_immediate(conn, sql)
        dict = ibm_db.fetch_assoc(stmt)
        if dict == False:
            return render_signin(False)
        if (mail == dict['EMAIL'].strip() and pwd == dict['PASSWORD'].strip()):
            return render_template("dashboard.html", user=dict['USERNAME'])
        else:
            return render_signin(False)
    return render_signin(True)

@app.route("/register", methods = ['POST', 'GET'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        roll = request.form['roll']
        pwd = request.form['password']
        insert_values(conn, email, name, roll, pwd)
        return redirect(url_for('checkLogin'))
    return render_template("register.html")


if __name__ == '__main__':
    app.debug = True
    app.run()