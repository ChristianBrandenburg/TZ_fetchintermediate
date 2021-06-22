from flask import Flask,render_template,request
import OpenSSL.crypto
import requests
 
app = Flask(__name__)
 
@app.route('/')
def form():
    return render_template('form.html')
 
@app.route('/data/', methods = ['POST', 'GET'])
def data():
    if request.method == 'GET':
        return f"The URL /data is accessed directly. Try going to '/' to submit form"
    if request.method == 'POST':
        form_data = request.form
        cert = form_data.get('text')
        pemcert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,cert)
        certdump = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, pemcert)
        attrlist = certdump.decode()

        for item in attrlist.split("\n"):
            if "Issuers" in item:
                aialine = item.strip()
        aiaurl = aialine[17:]
        r = requests.get(aiaurl)
        open('intermediate.crt', 'wb').write(r.content)
        opencert = open('intermediate.crt', "rb").read()
        dercert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1,opencert)
        certdump2 = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, dercert)
        attrlist2 = certdump2.decode()
        print(certdump2)
        return render_template('data.html',output = form_data, intermediate = certdump2)

app.run(host='localhost', port=5000)