from flask import Flask,render_template,request,redirect
import OpenSSL.crypto
import requests
 
app = Flask(__name__)
 
@app.route('/')
def form():
    return render_template('form.html')
 
@app.route('/submit/', methods = ['POST', 'GET'])
def data():
    # If the user goes directly to the submit page without submitting a cert
    if request.method == 'GET':
        return redirect('/')
    # Flow when the user submits a cert
    if request.method == 'POST':

        #Get data from form
        form_data = request.form
        cert = form_data.get('text')

        #Load the cert in as PEM and dump attributes 
        try:
            certload = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,cert)
            certdump = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, certload)
            certdecode = certdump.decode()

            #For dev 
            #print(attrlist)

            #Strip all attributes except the AIA URL
            for item in certdecode.split("\n"):
                if "Issuers" in item:
                    aialine = item.strip()
                if"Subject:" in item:
                    subjline = item.strip()
                if"Not Before:" in item:
                    startline = item.strip()
                if"Not After :" in item:
                    endline = item.strip()
                if"DNS:" in item:
                    sanline = item.strip()

            cnindex = subjline.index("CN=")
            certcn = subjline[cnindex+3:]

            aiaurl = aialine[17:]
            startline = startline[11:]
            endline = endline[11:]

            #For dev
            #print(sanline)

            #Go to the AIA URL, get intermediate and dump it as PEM
            imcertdownload = requests.get(aiaurl)
            open('intermediate.crt', 'wb').write(imcertdownload.content)
            imcert = open('intermediate.crt', "rb").read()
            loadimcert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1,imcert)
            imcertdump = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, loadimcert)
            intermediate = imcertdump.decode()

            imcerttxtdump = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, loadimcert)
            imcertdecode = imcerttxtdump.decode()

            print(imcertdecode)

            for item in imcertdecode.split("\n"):
                if"Subject:" in item:
                    imsubjline = item.strip()
                if"Not Before:" in item:
                    imstartline = item.strip()[11:]
                if"Not After :" in item:
                    imendline = item.strip()[11:]
            
            for item in imsubjline.split(","):
                if "O=" in item:
                    imorg = item[3:]
                if "CN=" in item:
                    imcn = item[4:]

        # If user post anything but a cert
        except:
            cert = "Error not a valid certificate"
            intermediate = ""

        return render_template('form.html',
        #Input cert and intermediate
        form_data = cert, intermediate = intermediate,
        #Certificate variables
        certcn = certcn, certsubj = subjline, certstart = startline, certend = endline, certsan = sanline,
        #Intermediate variables
        imorg = imorg, imcn = imcn, imstart = imstartline, imend = imendline
        )

app.run(host='localhost', port=5000)