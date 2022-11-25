from flask import Flask, render_template, request, redirect, session , make_response, url_for, json, flash
import re, ibm_db
import ibm_db_dbi
import pandas as pd
from flask_mail import Mail, Message
import os, datetime
from pandas import Timestamp
from pretty_html_table import build_table
import pdfkit


app = Flask(__name__)

app.secret_key = 'SECRET_KEY'

#IBM Database connection
conn = ibm_db.connect("DATABASE=bludb; HOSTNAME=b70af05b-76e4-4bca-a1f5-23dbb4c6a74e.c1ogj3sd0tgtu0lqde00.databases.appdomain.cloud; PORT=32716; SECURITY=SSL; SSLServerCertificate=DigiCertGlobalRootCA.crt; UID=fks81181;PWD=mdQZREsASRiq3Lb1",'','')
pd_conn = ibm_db_dbi.Connection(conn)

#HOME--PAGE
@app.route("/home")
def home():
    return render_template("homepage.html")

@app.route("/")
def add():
    return render_template("home.html")



#SIGN--UP--OR--REGISTER
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

        sql2 = 'SELECT * from REGISTER'
        stmt2 = ibm_db.prepare(conn, sql2)
        ibm_db.bind_param(stmt2, 1, username)
        ibm_db.execute(stmt2)

        register = ibm_db.fetch_assoc(stmt2)
        print(register)
        
        sql = 'SELECT * from REGISTER WHERE USERNAME = ?'
        stmt = ibm_db.prepare(conn, sql)
        ibm_db.bind_param(stmt, 1, username)
        ibm_db.execute(stmt)

        account = ibm_db.fetch_assoc(stmt)

        #print(account)
        if account:
            msg = 'Account already exists !'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address !'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'name must contain only characters and numbers !'
        else:
            sql = "INSERT INTO REGISTER(USER_ID,USERNAME,EMAIL,PASSWORD) VALUES(DEFAULT,?,?,?)"
            #sql = "INSERT into user values ('{}', '{}','{}', '{}')".format(default, username, email, password)
            #stmt = ibm_db.exec_immediate(conn, sql)
            
            stmt=ibm_db.prepare(conn,sql)
            print("stmt : ")
            print(stmt)
            ibm_db.bind_param(stmt,1,username)
            ibm_db.bind_param(stmt,2,email)
            ibm_db.bind_param(stmt,3,password)
            row = ibm_db.execute(stmt)
            
            #adding stuff to check databse insertion
            print("Number of affected rows: ", ibm_db.num_rows(stmt))
            
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
        
        sql = 'SELECT * from REGISTER WHERE USERNAME = ? AND PASSWORD = ?'
        stmt = ibm_db.prepare(conn, sql)
        ibm_db.bind_param(stmt, 1, username)
        ibm_db.bind_param(stmt, 2, password)
        ibm_db.execute(stmt)

        account = ibm_db.fetch_assoc(stmt)
        
        print (account)
        if account:
            session['loggedin'] = True
            session['id'] = account['USER_ID']
            userid =  account['USER_ID']
            session['username'] = account['USERNAME']
           
            return redirect('/add')
        else:
            msg = 'Incorrect username / password !'
    return render_template('login.html', msg = msg)




#ADDING----DATA
@app.route("/add")
def adding():

    return render_template('add.html')


@app.route('/addexpense',methods=['GET', 'POST'])
def addexpense():
    return redirect("/display")


#DISPLAY---graph 
@app.route("/display")
def display():
    if session.get("id")== None or session.get("username") == None:
        return redirect('/')

    print(session["username"],session['id'])
    
    id = str(session['id'])

    sql = 'SELECT * FROM EXPENSES WHERE USER_ID = {} ORDER BY DATE DESC'.format(id)
    df = pd.read_sql(sql,pd_conn)
    expense = df.values.tolist()

    print(expense)
  
    return render_template('display.html' ,expense = expense)
                          

 #limit
@app.route("/limit" )
def limit():
       return redirect('/limitn')

@app.route("/limitnum" , methods = ['POST' ])
def limitnum():
        return redirect('/limitn')
     
         
@app.route("/limitn") 
def limitn():

    return render_template("limit.html", type="Monthly",expense_data=monthly_expense, y=s)


#log-out
@app.route('/logout')
def logout():
   session.pop('loggedin', None)
   session.pop('id', None)
   session.pop('username', None)
   return render_template('home.html')

if __name__ == "__main__":
    app.run(debug=True)
