from flask import Flask, render_template, request, session, redirect, url_for, send_file
from password_utils import check_password_strength_web
import io
import csv

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # For session usage

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        password = request.form.get('password', '')
        result = check_password_strength_web(password)
        # Store result in session for exporting
        session['last_result'] = {
            'requirements': result['requirements'],
            'entropy': result['entropy'],
            'entropy_level': result['entropy_level'],
            'pwned_count': result['pwned_count']
        }
    return render_template('index.html', result=result)

@app.route('/export_csv')
def export_csv():
    last_result = session.get('last_result')
    if not last_result:
        return redirect(url_for('index'))
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Requirement', 'Met'])
    for req, met in last_result['requirements'].items():
        writer.writerow([req, 'OK' if met else 'Missing'])
    writer.writerow([])
    writer.writerow(['Entropy', last_result['entropy']])
    writer.writerow(['Entropy Level', last_result['entropy_level']])
    writer.writerow(['Pwned Count', last_result['pwned_count'] if last_result['pwned_count'] is not None else 'Not checked'])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype='text/csv', as_attachment=True, download_name='password_report.csv')

if __name__ == '__main__':
    app.run(debug=True)
