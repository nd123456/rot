from flask import Flask,render_template,request,session,redirect,url_for,flash,jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import login_user,logout_user,login_manager,LoginManager
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_admin import AdminIndexView, expose,Admin
from flask_admin.contrib import sqla as flask_admin_sqla
from flask_admin.contrib.sqla import ModelView
from flask_admin.menu import MenuLink
import pandas as pd
import openpyxl
from io import BytesIO
import sqlite3
from sqlalchemy import Enum
from enum import Enum as PyEnum
from flask_login import UserMixin
import re
from flask_migrate import Migrate
from flask_login import current_user



# MY db connection
local_server = True
app = Flask(__name__)
app.secret_key = 'netanyaclubms'


# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Set up database connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://club_ms_78kz_user:bqSZoUjIY1gFjHS1PrxwdXwgdhr1kfTG@dpg-cs2h8dbtq21c73ffb9vg-a.oregon-postgres.render.com/club_ms_78kz'
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
    role = db.Column(Enum('club_member', 'teacher', 'dean', 'admin', name='role_enum'), nullable=False)
    is_superuser = db.Column(db.Boolean, default=False)

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


class DefaultModelView(flask_admin_sqla.ModelView):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_superuser  # Change this if your user role is not 'admin'

    def inaccessible_callback(self, name, **kwargs):
        # Redirect to login page if user doesn't have access
        flash('Access denied. Admins only!', 'danger')  # Flash an error message
        return redirect(url_for('login'))  # Adjust to your login route

class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_superuser  # Ensure only superusers can access

    def inaccessible_callback(self, name, **kwargs):
        # Redirect to login page if user doesn't have access
        flash('Access denied. Admins only!', 'danger')  # Flash an error message
        return redirect(url_for('login'))  # Adjust to your login route

    @expose('/')
    def index(self):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))  # Redirect to login if not authenticated
        return super(MyAdminIndexView, self).index()

    @expose('/logout/')
    def logout_view(self):
        logout_user()
        session.clear()
        flash('You have been logged out.', 'success')
        return redirect(url_for('login'))  # Redirect to login after logout

# Initialize the Flask-Admin instance
admin = Admin(
    app,
    name='My Admin Panel',
    template_mode='bootstrap4',
    index_view=MyAdminIndexView()
)

# Add your model views
admin.add_view(DefaultModelView(User, db.session))  # Example model
admin.add_view(DefaultModelView(Request, db.session))  # Add your other models similarly
admin.add_view(DefaultModelView(Event, db.session))
admin.add_view(DefaultModelView(Attendance, db.session))
admin.add_view(DefaultModelView(ActivityPoints, db.session))
# Add a logout link in the admin menu
admin.add_link(MenuLink(name='Logout', url='/admin/logout'))




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
    return render_template('clubdash.html')

def validate_email(mail_id, role):
    if role == 'club_member':
        # Pattern for students: first.lastyy@rvce.edu.in (e.g., john.doe21@rvce.edu.in)
        student_pattern = r'^[a-z]+\.[a-z]{2}\d{2}@rvce\.edu\.in$'
        return re.match(student_pattern, mail_id) is not None, 'Invalid email'
    
    elif role == 'teacher':
        # Pattern for teachers: first@rvce.edu.in (e.g., john@rvce.edu.in)
        teacher_pattern = r'^[a-z]+@rvce\.edu\.in$'
        return re.match(teacher_pattern, mail_id) is not None, 'Invalid email'
    
    elif role == 'dean':
        # Fixed pattern for dean
        return mail_id == 'dean.studentaffairs@rvce.edu.in', 'Invalid Email'
    
    return False, 'Invalid role specified.'


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

        # Validate email based on role
        valid_email, email_message = validate_email(mail_id, role)
        if not valid_email:
            flash(email_message, 'danger')
            return render_template('register.html')

        # Validate password
        valid, message = validate_password(password)
        if not valid:
            flash(message, 'Invalid Password')
            return render_template('register.html')

        # Hash the password before saving
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Create a new user object
        new_user = User(mail_id=mail_id, password=hashed_password, role=role,is_superuser=False)

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
        if user and user.role == 'admin' and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('admin.index'))  # Redirect to the admin page after login
        elif user and check_password_hash(user.password, password):
            login_user(user)
            session['mail_id'] = user.mail_id
            session['role'] = user.role
            return redirect(url_for('club_dashboard'))  # Redirect to the updated route name
        else:
            flash('Invalid email, password, or role. Please try again.', 'danger')
            return render_template('login.html')
    return render_template('login.html')

@app.route('/teacher_dashboard')
def teacher_dashboard():
    if 'mail_id' not in session or session.get('role') == 'club_member':
        return redirect(url_for('login'))
    return render_template('councellor.html')

@app.route('/club_dashboard')
def club_dashboard():  # Updated function name to match the route
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
        usn_pattern = r'^1RV[0-9]{2}[A-Z]{2}[0-9]{3}$'

        # Check if the USN matches the required pattern
        if not re.match(usn_pattern, usn):
            flash('Invalid USN format. Please enter a valid USN (e.g., 1RVXXYYZZZ).', 'danger')
            return redirect(url_for('add_attendance'))

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
        usn_pattern = r'^1RV[0-9]{2}[A-Z]{2}[0-9]{3}$'

        # Check if the USN matches the required pattern
        if not re.match(usn_pattern, usn):
            flash('Invalid USN format. Please enter a valid USN (e.g., 1RVXXYYZZZ).', 'danger')
            return redirect(url_for('add_attendance'))

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

    # Calculate total points only if USN filter is applied and no other filters
    if usn and len(filters) == 1:  # Only USN filter is applied
        total_points = sum(activity_point.points_alloted for activity_point in activity_points)
    else:
        total_points = None  # Or set to 0 if you prefer

    return render_template('view_activity_points.html', activity_points=activity_points, events=events, total_points=total_points)

@app.route('/achievements')
def achievements():
    return render_template('achievements.html')

@app.route('/contactus')
def contactus():
    return render_template('contactus.html')


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
    events_to_delete = Event.query.filter_by(name=event_name, description=event_description).all()
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


def create_super_user():
    with app.app_context():
        # Check if the super user already exists
        existing_super_user = User.query.filter_by(role='admin', is_superuser=True).first()

        if not existing_super_user:
            # Prompt for super user details
            super_user_email = 'rotaractadmin@rvce.edu.in'  # Set your super user email
            super_user_password = 'ADMINaccess'  # Set your super user password
            
            # Create the super user
            super_user = User(
                mail_id=super_user_email,
                password=generate_password_hash(super_user_password, method='pbkdf2:sha256'),
                role='admin',
                is_superuser=True
            )

            # Add to session and commit to the database
            db.session.add(super_user)
            db.session.commit()
            print("Super user created successfully.")
        else:
            print("Super user already exists.")

@app.route('/download_activity_points_excel')
def download_activity_points_excel():
    # Get filters from query string
    usn_filter = request.args.get('usn', '')
    department_filter = request.args.get('department', '')
    event_filter = request.args.get('event', '')

    # Build the query with filters
    query = ActivityPoints.query

    if usn_filter:
        query = query.filter(ActivityPoints.USN.ilike(f'%{usn_filter}%'))

    if department_filter:
        query = query.filter_by(department=department_filter)

    if event_filter:
        query = query.filter_by(event_name=event_filter)

    # Execute the query to get the filtered results
    activity_points = query.all()

    # Prepare data for the DataFrame
    data = []
    for point in activity_points:
        data.append({
            'USN': point.USN,
            'Student Name': point.student_name,
            'Department': point.department,
            'Event Name': point.event_name,
            'Event Date': point.event_date.strftime('%Y-%m-%d'),  # Format date as needed
            'Points Allotted': point.points_alloted
        })

    # Create a DataFrame from the filtered data
    df = pd.DataFrame(data)

    # Create a BytesIO buffer to write the Excel data
    output = BytesIO()

    # Write the DataFrame to the Excel file
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Activity Points')

    # Return the file as a downloadable response
    output.seek(0)
    return make_response(output.getvalue(), {
        'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'Content-Disposition': 'attachment; filename=activity_points_filtered.xlsx'
    })

@app.route('/download_attendance_excel')
def download_attendance_excel():
    # Get the search query from the request
    query = request.args.get('query', '')

    # Start the base query
    query_result = Attendance.query

    # Apply filter if search query is present
    if query:
        query_result = query_result.filter(
            (Attendance.USN.ilike(f'%{query}%')) |
            (Attendance.student_name.ilike(f'%{query}%')) |
            (Attendance.department.ilike(f'%{query}%')) |
            (Attendance.event_name.ilike(f'%{query}%'))
        )

    # Execute the query to get the filtered attendance records
    attendances = query_result.all()

    # Prepare data for the DataFrame
    data = []
    for attendance in attendances:
        data.append({
            'USN': attendance.USN,
            'Student Name': attendance.student_name,
            'Department': attendance.department,
            'Event Name': attendance.event_name,
            'Start Date': attendance.start_date.strftime('%Y-%m-%d'),
            'End Date': attendance.end_date.strftime('%Y-%m-%d')
        })

    # Create a DataFrame from the filtered data
    df = pd.DataFrame(data)

    # Create a BytesIO buffer to write the Excel data
    output = BytesIO()

    # Write the DataFrame to an Excel file in memory
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Attendance')

    # Return the file as a downloadable response
    output.seek(0)
    return make_response(output.getvalue(), {
        'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'Content-Disposition': 'attachment; filename=attendance_filtered.xlsx'
    })

if __name__=='__main__':
    with app.app_context():
        db.create_all()  # This will create all tables
    create_super_user()
    app.run(debug=True)