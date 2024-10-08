from flask import Flask,render_template,request,session,redirect,url_for,flash,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import login_user,logout_user,login_manager,LoginManager
from flask_mysqldb import MySQL
import MySQLdb.cursors
import sqlite3
from flask_login import UserMixin
import re
from flask_migrate import Migrate


# MY db connection
local_server = True
app = Flask(__name__)
app.secret_key = 'netanyaclubms'


# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Set up database connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://club_ms_user:WSiZdlbB3toVnAFQ9kIp0o9ObTz1wEPc@dpg-cs2fh6jqf0us73a6vovg-a.ohio-postgres.render.com/club_ms'
#app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)


# this is for getting unique user access
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(mail_id):
    return User.query.get(mail_id)

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    mail_id = db.Column(db.String(64), primary_key=True)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.Enum('club_member', 'teacher', 'dean', name='role_enum'), nullable=False)

    def get_id(self):
        return self.mail_id

# Define Event model
class Event(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.String(256))

# Define Request model
class Request(db.Model):
    __tablename__ = 'requests'
    id = db.Column(db.Integer, primary_key=True)
    event_name = db.Column(db.String(128), nullable=False)
    event_description = db.Column(db.String(256))
    status = db.Column(db.Enum('pending', 'approved', 'denied', name='status_enum'), nullable=False)

# Define Attendance model
class Attendance(db.Model):
    __tablename__ = 'attendance'
    id = db.Column(db.Integer, primary_key=True)
    USN = db.Column(db.String(20), nullable=False)
    student_name = db.Column(db.String(128), nullable=False)
    department = db.Column(db.String(128), nullable=False)
    event_name = db.Column(db.String(128), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)

# Define ActivityPoints model
class ActivityPoints(db.Model):
    __tablename__ = 'activity_points'
    id = db.Column(db.Integer, primary_key=True)
    USN = db.Column(db.String(20), nullable=False)
    student_name = db.Column(db.String(128), nullable=False)
    department = db.Column(db.String(128), nullable=False)
    event_name = db.Column(db.String(128), nullable=False)
    event_date = db.Column(db.Date, nullable=False)
    points_alloted = db.Column(db.Integer, nullable=False)

# Simulated data structure to store events
events = []

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character."
    return True, ""

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        mail_id = request.form['mail_id']
        password = request.form['password']
        role = request.form['role']

        # Check if the username already exists
        existing_user = User.query.filter_by(mail_id=mail_id).first()
        if existing_user:
            flash('Username already exists! Please choose a different username.', 'danger')
            return render_template('register.html')

        # Check if the email is from RVCE domain
        if not mail_id.endswith('@rvce.edu.in'):
            flash('Only RVCE email IDs can be used for registration.', 'danger')
            return render_template('register.html')

        # Validate password
        valid, message = validate_password(password)
        if not valid:
            flash(message, 'Invalid Password')
            return render_template('register.html')

        # Hash the password before saving
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Create a new user object
        new_user = User(mail_id=mail_id, password=hashed_password, role=role)

        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        mail_id = request.form['mail_id']
        password = request.form['password']
        role = request.form['role']

        # Check if the user exists and the password is correct
        user = User.query.filter_by(mail_id=mail_id, role=role).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            session['mail_id'] = user.mail_id
            session['role'] = user.role
            return redirect(url_for('club_dashboard'))  # Redirect to the updated route name
        else:
            flash('Invalid email, password, or role. Please try again.', 'danger')

    return render_template('login.html')

@app.route('/teacher_dashboard')
def teacher_dashboard():
    if 'mail_id' not in session or session.get('role') == 'club_member':
        return redirect(url_for('login'))
    return render_template('councellor.html')

@app.route('/club_dashboard')
def club_dashboard():  # Updated function name to match the route
    if 'mail_id' not in session:
        return redirect(url_for('login'))
    return render_template('clubdash.html')


@app.route('/logout')
def logout():
    logout_user()
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/events_permission')
def events_permission():
    if 'mail_id' not in session or session.get('role') != 'club_member':
        return redirect(url_for('login'))
    try:
        events = Request.query.all()
        return render_template('events_permission.html', events=events)
    except Exception as e:
        return f"An error occurred: {str(e)}"

@app.route('/add_event', methods=['POST'])
def add_event():
    if 'mail_id' not in session or session.get('role') != 'club_member':
        return redirect(url_for('login'))
    event_name = request.form['event_name']
    event_description = request.form['event_description']
    try:
        new_request = Request(event_name=event_name, event_description=event_description, status='pending')
        db.session.add(new_request)
        db.session.commit()
        flash('Event request added successfully.', 'success')
        return redirect(url_for('events_permission'))
    except Exception as e:
        return f"An error occurred: {str(e)}"

@app.route('/add_attendance', methods=['GET', 'POST'])
def add_attendance():
    if 'mail_id' not in session or session.get('role') != 'club_member':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        usn = request.form['usn']
        student_name = request.form['student_name']
        department = request.form['department']
        event_name = request.form['event_name']
        start_date = request.form['start_date']
        end_date = request.form['end_date']

        attendance = Attendance(USN=usn, student_name=student_name, department=department,
                                event_name=event_name, start_date=start_date, end_date=end_date)
        db.session.add(attendance)
        db.session.commit()

        flash('Attendance added successfully.', 'success')
        return redirect('/add_attendance')
    else:
        events = Event.query.all()  # Fetch all events from the database
        return render_template('add_attendance.html', events=events)

@app.route('/view_attendance')
def view_attendance():
    if 'mail_id' not in session or session.get('role') == 'dean':
        return redirect(url_for('login'))
    attendances = Attendance.query.all()
    return render_template('view_attendance.html', attendances=attendances)

@app.route('/search_attendance')
def search_attendance():
    query = request.args.get('query')
    attendances = Attendance.query.filter(
        (Attendance.department.like(f'%{query}%')) |
        (Attendance.USN.like(f'%{query}%')) |
        (Attendance.event_name.like(f'%{query}%'))
    ).all()
    return render_template('view_attendance.html', attendances=attendances)

@app.route('/data')
def get_data():
    results = db.session.query(Attendance.event_name, db.func.count(Attendance.id)).group_by(Attendance.event_name).all()
    data = {
        'eventNames': [result[0] for result in results],
        'participationCounts': [result[1] for result in results]
    }
    return jsonify(data)

@app.route('/add_activity_points', methods=['GET', 'POST'])
def add_activity_points():
    if 'mail_id' not in session or session.get('role') != 'club_member':
        return redirect(url_for('login'))
    if request.method == 'POST':
        department = request.form['department']
        usn = request.form['usn']
        student_name = request.form['student_name']
        event_name = request.form['event_name']
        event_date = request.form['event_date']
        points_alloted = int(request.form['points_alloted'])

        activity_points = ActivityPoints(department=department, USN=usn, student_name=student_name,
                                         event_name=event_name, event_date=event_date, points_alloted=points_alloted)
        db.session.add(activity_points)
        db.session.commit()

        flash('Activity points added successfully.', 'success')
        return redirect('/add_activity_points')
    else:
        events = Event.query.all()  # Fetch all events from the database
        return render_template('add_activity_points.html',events=events)

@app.route('/view_activity_points', methods=['GET'])
def view_activity_points():
    if 'mail_id' not in session or session.get('role') == 'dean':
        return redirect(url_for('login'))
    usn = request.args.get('usn', None)
    department = request.args.get('department', None)
    event = request.args.get('event', None)
    events = Event.query.all()

    filters = []
    if usn:
        filters.append(ActivityPoints.USN == usn)
    if department:
        filters.append(ActivityPoints.department == department)
    if event:
        filters.append(ActivityPoints.event_name == event)

    if filters:
        activity_points = ActivityPoints.query.filter(*filters).all()
    else:
        activity_points = ActivityPoints.query.all()

    return render_template('view_activity_points.html', activity_points=activity_points,events=events)

@app.route('/achievements')
def achievements():
    return render_template('achievements.html')


@app.route('/requests')
def requests_dashboard():
    # Fetch all requests from the database
    requests = Request.query.all()
    return render_template('view_request.html', requests=requests)

@app.route('/view_request/<int:request_id>', methods=['GET', 'POST'])
def view_request_detail(request_id):
    if 'mail_id' not in session or session.get('role') != 'dean':
        return redirect(url_for('login'))
    
    req = Request.query.get(request_id)  # Fetch the request object
    if req is None:
        flash('Request not found.', 'error')
        return redirect(url_for('requests'))
    
    if request.method == 'POST':
        new_status = request.form['status']
        try:
            req.status = new_status
            if new_status == 'approved':
                # Create a new event based on the request details
                new_event = Event(name=req.event_name, description=req.event_description)
                db.session.add(new_event)
            
            # Commit the transaction after adding the event
            db.session.commit()

            flash('Request updated successfully.', 'success')
        except Exception as e:
            db.session.rollback()  # Rollback the transaction in case of an error
            flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('requests_dashboard'))
    
    return render_template('view_request_detail.html', request=req)


@app.route('/delete_event/<int:request_id>', methods=['POST'])
def delete_event(request_id):
    if 'mail_id' not in session or session.get('role') != 'club_member':
        return redirect(url_for('login'))
    req = Request.query.get_or_404(request_id)
    
    event_name = req.event_name
    event_description = req.event_description
    db.session.delete(req)
    events_to_delete = Event.query.filter_by(event_name=event_name, event_description=event_description).all()
    for event in events_to_delete:
        db.session.delete(event)

    db.session.commit()

    flash('Event request and associated events deleted successfully.', 'success')
    return redirect(url_for('events_permission'))



@app.route('/delete_attendance/<int:attendance_id>', methods=['POST'])
def delete_attendance(attendance_id):
    if 'mail_id' not in session or session.get('role') != 'club_member':
        return redirect(url_for('login'))
    
    attendance = Attendance.query.get_or_404(attendance_id)
    db.session.delete(attendance)
    db.session.commit()
    
    flash('Attendance record deleted successfully.', 'success')
    return redirect(url_for('view_attendance'))


@app.route('/delete_activity_point/<int:activity_point_id>', methods=['POST'])
def delete_activity_point(activity_point_id):
    if 'mail_id' not in session or session.get('role') != 'club_member':
        return redirect(url_for('login'))
    
    activity_point = ActivityPoints.query.get_or_404(activity_point_id)
    db.session.delete(activity_point)
    db.session.commit()
    
    flash('Activity point deleted successfully.', 'success')
    return redirect(url_for('view_activity_points'))


if __name__=='__main__':
    with app.app_context():
        db.create_all()  # This will create all tables
    app.run(debug=True)