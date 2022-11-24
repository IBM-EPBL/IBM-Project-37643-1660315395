from flask import Flask, render_template, request, redirect, session , make_response, url_for, json, flash
import re, ibm_db
from flask_bcrypt import Bcrypt 
import ibm_db_dbi ,pandas as pd
from flask_mail import Mail, Message
import os, datetime
from pandas import Timestamp
from pretty_html_table import build_table
import pdfkit


app = Flask(__name__)

app.secret_key = 'SECRET_KEY'

#added for bcrypt
bcrypt = Bcrypt(app)

#IBM Database Connection
conn = ibm_db.connect("DATABASE=bludb; HOSTNAME=b70af05b-76e4-4bca-a1f5-23dbb4c6a74e.c1ogj3sd0tgtu0lqde00.databases.appdomain.cloud; PORT=32716; SECURITY=SSL; SSLServerCertificate=DigiCertGlobalRootCA.crt; UID=fks81181;PWD=mdQZREsASRiq3Lb1",'','')
pd_conn = ibm_db_dbi.Connection(conn)

#HOMEPAGE
@app.route("/home")
def home():
    return render_template("homepage.html")

@app.route("/")
def add():
    return render_template("home.html")

#SIGNUP OR REGISTER
@app.route("/signup")
def signup():
    return render_template("signup.html")

@app.route('/register', methods =['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' :
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        #added for bcrypt
        password = bcrypt.generate_password_hash(password)
        
        sql = 'SELECT * from REGISTER WHERE USERNAME = ?'
        stmt = ibm_db.prepare(conn, sql)
        ibm_db.bind_param(stmt, 1, username)
        ibm_db.execute(stmt)

        account = ibm_db.fetch_assoc(stmt)

        print(account)
        if account:
            msg = 'Account already exists !'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address !'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'name must contain only characters and numbers !'
        else:
            sql = "INSERT INTO REGISTER(USER_ID,USERNAME,EMAIL,PASSWORD) VALUES(DEFAULT,?,?,?)"
            stmt=ibm_db.prepare(conn,sql)
            ibm_db.bind_param(stmt,1,username)
            ibm_db.bind_param(stmt,2,email)
            ibm_db.bind_param(stmt,3,password)
            ibm_db.execute(stmt)

            msg = 'You have successfully registered !'
        return render_template('signup.html', msg = msg)
                
#LOGIN--PAGE
@app.route("/signin")
def signin():
    return render_template("login.html")
        
@app.route('/login',methods =['GET', 'POST'])
def login():
    global userid
    msg = ''
   
    if request.method == 'POST' :
        username = request.form['username']
        password = request.form['password'] 
        
        sql = 'SELECT * from REGISTER WHERE USERNAME = ?'
        stmt = ibm_db.prepare(conn, sql)
        ibm_db.bind_param(stmt, 1, username)
        
        ibm_db.execute(stmt)
       
        account = ibm_db.fetch_assoc(stmt)
        
        print (account)
        #changed to add bcrypt
        if account and bcrypt.check_password_hash(account['PASSWORD'], password) :
            session['loggedin'] = True
            session['id'] = account['USER_ID']
            userid =  account['USER_ID']
            session['username'] = account['USERNAME']
           
            return redirect('/dashboard')
        else:
            msg = 'Incorrect username / password !'
    return render_template('login.html', msg = msg)

#Logout
@app.route('/logout')
def logout():
   session.pop('loggedin', None)
   session.pop('id', None)
   session.pop('username', None)
   return render_template('home.html')

#DASHBOARD
@app.route("/dashboard")
def adding():
    if session.get("id")== None or session.get("username") == None:
        return redirect('/')

    return render_template('dashboard.html')

if __name__ == "__main__":
    app.run(debug=True)
