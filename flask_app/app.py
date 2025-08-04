from flask import Flask, render_template, request
from password_utils import check_password_strength_web

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        password = request.form.get('password', '')
        result = check_password_strength_web(password)
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
