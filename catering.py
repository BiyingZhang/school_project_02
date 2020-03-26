#Biying Zhang CS1520 Project2
import os
from datetime import datetime
from hashlib import md5
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc
from flask import Flask, request, session, url_for, redirect, render_template, abort, g, flash
from werkzeug import check_password_hash, generate_password_hash

from models import db, User, Event
app = Flask(__name__)

DEBUG = True
SECRET_KEY = 'super secure'

SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(app.root_path, 'catering.db')

app.config.from_object(__name__)
app.config.from_envvar('CATERING_SETTINGS', silent=True)

db.init_app(app)

@app.cli.command('initdb')
def initdb():
	db.create_all()
	#if owner doesn't exist add owner
	if User.query.filter_by(username="owner").first() is None:
		db.session.add(User("owner", "Owner", generate_password_hash("pass")))
	db.session.commit()
	print('Initialized the database.')

def get_user_username(username):
	u = User.query.filter_by(username=username).first()
	return u.username if u else None

def get_user_id(username):
	u = User.query.filter_by(username=username).first()
	return u.id if u else None

def get_user_role(username):
	u = User.query.filter_by(username=username).first()
	return u.role if u else None

#redirects a user to proper page
def redirectToRightPage():
	if g.user == None:
		return redirect(url_for('login_controller'))

	role = get_user_role(session['username'])
	if role == "Owner":
		return redirect(url_for('owner_controller'))
	elif role == "Staff":
		return redirect(url_for('staff_controller'))
	elif role == "Customer":
		return redirect(url_for('customer_controller'))
	else:
		return "This user's role does not exist"

@app.before_request
def before_request():
	g.user = None
	if 'username' in session:
		g.user = User.query.filter_by(username=session['username']).first()

@app.route("/")
def default():
	if not g.user:
		return redirect(url_for('login_controller'))
	else:
		return redirectToRightPage();

@app.route('/login', methods=['GET', 'POST'])
def login_controller():
	error = None
	if g.user:
		return redirectToRightPage()
		#do something redirect return redirect(url_for("main", username=session["username"]))
		#return "ahhh logged in testing"
	if request.method == 'POST':
		user = User.query.filter_by(username=request.form['username']).first()
		if user is None:
			error = 'Invalid username' #did not find this user in db
		elif not check_password_hash(user.pw_hash, request.form['password']):
			error = 'Invalid password'
		else:
			flash('You were logged in')
			session['username'] = user.username
			return redirectToRightPage()
	return render_template('login.html', error=error)

@app.route('/logout')
def logout():
	"""Logs the user out."""
	flash('You were logged out')
	session.pop('username', None)
	return redirect(url_for('login_controller'))

@app.route('/register', methods=['GET', 'POST'])
def register():
	error = None
	if g.user and g.user.role != "Owner":
		return redirectToRightPage()

	if request.method == "POST":
		if not request.form['username']:
			error = "You have to enter a username"
		elif not request.form['password']:
			error = "You have to enter a password"
		elif request.form['password'] != request.form['password2']:
			error = 'The two passwords do not match'
		elif get_user_username(request.form['username']) is not None:
			error = 'The username is already taken'
		else:
			if g.user and g.user.role == "Owner":
				db.session.add(User(request.form['username'], "Staff", generate_password_hash(request.form['password'])))
				db.session.commit()
				flash('You successfully registered a staff account with username: ' + request.form['username'])
				return redirect(url_for('owner_controller'))
			else:
				db.session.add(User(request.form['username'], "Customer", generate_password_hash(request.form['password'])))
				db.session.commit()
				flash('You successfully registered a new customer account with username: ' + request.form['username'])
				return redirect(url_for('login_controller'))
	return render_template("register.html", error=error)


@app.route("/owner", methods=['GET', 'POST'])
def owner_controller():
	if not g.user or get_user_role(session['username']) != "Owner":
		return redirectToRightPage()

	error = None
	if request.method == "POST":
		if not request.form['username']:
			error = "You have to enter a username"
		elif not request.form['password']:
			error = "You have to enter a password"
		elif request.form['password'] != request.form['password2']:
			error = 'The two passwords do not match'
		elif get_user_username(request.form['username']) is not None:
			error = 'The username is already taken'
		else:
			db.session.add(User(request.form['username'], "Staff", generate_password_hash(request.form['password'])))
			db.session.commit()
			flash('You successfully registered a staff account with username: ' + request.form['username'])
	return render_template('owner.html', error=error, events=Event.query.all())

@app.route("/staff", methods=['GET', 'POST'])
def staff_controller():
	if not g.user or get_user_role(session['username']) != "Staff":
		return redirectToRightPage()
	else:
		staff = User.query.filter_by(username=session['username']).first()
		scheduled = Event.query.filter(Event.workingStaff.contains(staff)).all()
		openEvents = Event.query.filter(~Event.workingStaff.contains(staff), Event.open==True).all()
		return render_template('staff.html', scheduled=scheduled, openEvents=openEvents)

@app.route("/staff/<eventid>", methods=['GET', 'POST'])
def eventSignUp(eventid):
	if not g.user or get_user_role(session['username']) != "Staff":
		return redirectToRightPage()
	staff = User.query.filter_by(username=session['username']).first()
	e = Event.query.filter_by(id=eventid).first()
	if not(e in staff.signedEvents) and (e.open == True):
		staff.signedEvents.append(e)
		db.session.commit()
		if len(list(str(e.workingStaff)[1:-1].split(", "))) == 3:
			e.open = False
			db.session.commit()
		flash("You have successfully signed up for event: " + e.eventname)
	return redirect(url_for("staff_controller"))


@app.route("/staff/unsign/<eventid>", methods=['GET', 'POST'])
def eventUnsign(eventid):
	if not g.user or get_user_role(session['username']) != "Staff":
		return redirectToRightPage()
	staff = User.query.filter_by(username=session['username']).first()
	e = Event.query.filter_by(id=eventid).first()

	if e in staff.signedEvents:
		staff.signedEvents.remove(e)
		if len(list(str(e.workingStaff)[1:-1].split(", "))) < 3:
			e.open = True
		db.session.commit()
		flash("You have successfully removed yourself from event: " + e.eventname)
	return redirect(url_for("staff_controller"))


@app.route("/customer", methods=['GET', 'POST'])
def customer_controller():
	if not g.user or get_user_role(session['username']) != "Customer":
		return redirectToRightPage()
	else:
		error = None
		if request.method == "POST":
			if not request.form['eventName']:
				error = "You have to enter an event name"
			elif not request.form['eventDate']:
				error = "You have to enter an event name"
			elif Event.query.filter_by(eventname=request.form['eventName']).first():
				error = "This event already exists"
			#TODO: check date format and  *safari
			elif Event.query.filter_by(date=request.form['eventDate']).first():
				error = "There is already an event on the day you chose"
			else:
				db.session.add(Event(request.form['eventName'], request.form['eventDate'], session['username']))
				db.session.commit()
				flash('You successfully registered an event named {} on {}.'.format(request.form['eventName'], request.form['eventDate']))


	events = Event.query.filter_by(requester=session['username']).all()
	today = datetime.today().strftime('%Y-%m-%d')
	return render_template('customer.html', events=events, error=error, minDate=today)

@app.route("/customer/<event>", methods=['GET', 'POST'])
def cancel_event(event):
	if not g.user or g.user.username != Event.query.filter_by(eventname=event).first().requester:
		return redirectToRightPage()
	#delete event
	Event.query.filter_by(eventname=event).delete()
	db.session.commit()
	flash('You have successfully canceled the event ' + event )
	return redirect(url_for('customer_controller'))

# @app.route("/main")
# def main_controller():
# 	if !"username" in session:
# 		return redirect(url_for("login_controller"))
# 	else:
# 		if #if user role is owner ==> create new user
# 		elif #if user role is client
# 		elif #if user role is staff
# 		else #user role not recognized
# 			throw some sort of error

if __name__ == "__main__":
	app.run()






#TODO: unify date input
# 		check if there are already three staff
# 		user see staff who signed up
