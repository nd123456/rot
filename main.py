from flask import Flask,render_template,request,session,redirect,url_for,flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import login_user,logout_user,login_manager,LoginManager
from flask_mysqldb import MySQL
import MySQLdb.cursors
import sqlite3


# MY db connection
local_server = True
app = Flask(__name__)
app.secret_key = 'netanyaclubms'




# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Set up database connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost:3307/cmsys'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# this is for getting unique user access
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model):
    __tablename__='users'
    mail_id = db.Column(db.String(64), primary_key=True)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.Enum('club_member', 'teacher', 'dean'), nullable=False)

# Define Event model
class Event(db.Model):
    __tablename__='events'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.String(256))
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)

# Define Request model
class Request(db.Model):
    __tablename__='requests'
    id = db.Column(db.Integer, primary_key=True)
    event_name = db.Column(db.String(128), nullable=False)
    event_description = db.Column(db.String(256))
    status = db.Column(db.Enum('pending', 'approved', 'denied'), nullable=False)

# Define Attendance model
class Attendance(db.Model):
    __tablename__='attendance'
    id = db.Column(db.Integer, primary_key=True)
    USN = db.Column(db.String(20), nullable=False)
    student_name = db.Column(db.String(128), nullable=False)
    department = db.Column(db.String(128), nullable=False)
    event_name = db.Column(db.String(128), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)

# Define ActivityPoints model
class ActivityPoints(db.Model):
    __tablename__='activity_points'
    id = db.Column(db.Integer, primary_key=True)
    USN = db.Column(db.String(20), nullable=False)
    student_name = db.Column(db.String(128), nullable=False)
    department = db.Column(db.String(128), nullable=False)
    event_name = db.Column(db.String(128), nullable=False)
    event_date = db.Column(db.Date, nullable=False)
    points_alloted = db.Column(db.Integer, nullable=False)

# Simulated data structure to store events
events = []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        mail_id= request.form['mail_id']
        password = request.form['password']
        role = request.form['role']

        # Check if the username already exists
        existing_user = User.query.filter_by(mail_id=mail_id).first()
        if existing_user:
            return 'Username already exists! Please choose a different username.'

        # Check if the email is from RVCE domain
        if not mail_id.endswith('@rvce.edu.in'):
            return 'Only RVCE email IDs can be used for registration.'

        # Create a new user object
        new_user = User(mail_id=mail_id, password=password, role=role)

        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('index'))  # Redirect to the homepage after successful registration

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        mail_id = request.form['mail_id']
        password = request.form['password']
        role = request.form['role']

        # Check if the user exists and the password is correct
        user = User.query.filter_by(mail_id=mail_id, password=password, role=role).first()
        if user:
            session['mail_id'] = user.mail_id
            session['role'] = user.role
            if user.role == 'club_member':
                return redirect(url_for('clubmemberdash'))
            elif user.role == 'teacher':
                return redirect(url_for('teacher_dashboard'))
            elif user.role == 'dean':
                return redirect(url_for('dean_dashboard'))
        else:
            return 'Invalid email, password, or role. Please try again.'

    return render_template('login.html')  # Render the login.html template for GET requests

@app.route('/club_member_dashboard')
def clubmemberdash():
    if 'mail_id' not in session or session.get('role') != 'club_member':
        return redirect(url_for('login'))  # Redirect to login if not authenticated or not a club member
    return render_template('clubmemberdash.html')


@app.route('/events_permission')
def events_permission():
    try:
        # Fetch all entries from the requests table
        events = Request.query.all()
        return render_template('events_permission.html', events=events)
    except Exception as e:
        return f"An error occurred: {str(e)}"


@app.route('/add_event', methods=['POST'])
def add_event():
    event_name = request.form['event_name']
    event_description = request.form['event_description']
    try:
        # Create a new Request object with the event details
        new_request = Request(event_name=event_name, event_description=event_description,
                              status='pending')

        # Add the new request to the session and commit the transaction
        db.session.add(new_request)
        db.session.commit()
        return redirect(url_for('events_permission'))
    except Exception as e:
        return f"An error occurred: {str(e)}"
    
@app.route('/add_attendance', methods=['GET', 'POST'])
def add_attendance():
    if request.method == 'POST':
        usn = request.form['usn']
        student_name = request.form['student_name']
        department = request.form['department']
        event_name = request.form['event_name']
        start_date = request.form['start_date']
        end_date = request.form['end_date']

        # Create a new Attendance object
        attendance = Attendance(USN=usn, student_name=student_name, department=department,
                                event_name=event_name, start_date=start_date, end_date=end_date)

        # Add the new attendance record to the database
        db.session.add(attendance)
        db.session.commit()

        # Redirect to a success page or another appropriate route
        return redirect('/add_attendance')
    else:
        return render_template('add_attendance.html')
    
@app.route('/view_attendance')
def view_attendance():
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

@app.route('/add_activity_points', methods=['GET', 'POST'])
def add_activity_points():
     if request.method == 'POST':
        department = request.form['department']
        usn = request.form['usn']
        student_name = request.form['student_name']
        event_name = request.form['event_name']
        event_date = request.form['event_date']
        points_alloted = int(request.form['points_alloted'])

    # Create a new ActivityPoints object
        activity_points = ActivityPoints(department=department, USN=usn, student_name=student_name,
                                     event_name=event_name, event_date=event_date, points_alloted=points_alloted)

    # Add the new activity points record to the database
        db.session.add(activity_points)
        db.session.commit()

    # Redirect to a success page or another appropriate route
        return redirect('/add_activity_points')
     else:
         return render_template('add_activity_points.html')
         
@app.route('/view_activity_points', methods=['GET'])
def view_activity_points():
    # Get filter parameters from the query string
    usn = request.args.get('usn', None)
    department = request.args.get('department', None)
    event = request.args.get('event', None)

    # Build the filter conditions
    filters = []
    if usn:
        filters.append(ActivityPoints.USN == usn)
    if department:
        filters.append(ActivityPoints.department == department)
    if event:
        filters.append(ActivityPoints.event_name == event)

    # Fetch activity points based on filters
    if filters:
        activity_points = ActivityPoints.query.filter(*filters).all()
    else:
        activity_points = ActivityPoints.query.all()

    return render_template('view_activity_points.html', activity_points=activity_points)

@app.route('/achievements')
def achievements():
    # This route will render the achievements page
    return render_template('achievements.html')

if __name__=='__main__':
    app.run(debug=True)