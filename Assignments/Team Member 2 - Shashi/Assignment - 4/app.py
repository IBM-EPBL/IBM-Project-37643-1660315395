from flask import Flask
import os
app = Flask(__name__)

@app.route("/")
def home():
    return "Job Portal! Hello!!"

if __name__=="__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(port=port, host='0.0.0.0')
