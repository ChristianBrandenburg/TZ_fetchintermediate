from flask import Flask,render_template,request,redirect
import OpenSSL.crypto
import requests
 
app = Flask(__name__)
 
@app.route('/')
def form():
    return render_template('form.html')
 
@app.route('/data/', methods = ['POST', 'GET'])
def data():
    # If the user goes directly to the result page without submitting a cert
    if request.method == 'GET':
        return redirect('/')
    # Flow when the user submits a cert
    if request.method == 'POST':

        #Get data from form
        form_data = request.form
        cert = form_data.get('text')

        #Load the cert in as PEM and dump attributes 
        pemcert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,cert)
        certdump = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, pemcert)
        attrlist = certdump.decode()

        #Strip all attributes except the AIA URL
        for item in attrlist.split("\n"):
            if "Issuers" in item:
                aialine = item.strip()
        aiaurl = aialine[17:]

        #Go to the AIA URL, get intermediate and dump it as PEM
        r = requests.get(aiaurl)
        open('intermediate.crt', 'wb').write(r.content)
        opencert = open('intermediate.crt', "rb").read()
        dercert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1,opencert)
        certdump2 = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, dercert)
               
        attrlist2 = certdump2.decode()
        print(certdump2)
        return render_template('form.html',output = form_data, intermediate = attrlist2)

app.run(host='localhost', port=5000)