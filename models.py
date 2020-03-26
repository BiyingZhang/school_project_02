from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

schedule = db.Table("schedule",
	db.Column('user_id', db.Integer, db.ForeignKey('User.id')),
	db.Column('event_id', db.Integer, db.ForeignKey('Event.id'))
)

class User(db.Model):
	__tablename__ = "User"
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(30), unique=True, nullable=False)
	role = db.Column(db.String(24), nullable=False)
	pw_hash = db.Column(db.String(64), nullable=False)
	#attribute/field
	#events = db.Column(db.Integer, db.ForeignKey('Event.id'))
	#eventSignedUp = db.relationship('Event', secondary="schedule", backref=db.backref('signedEvents', lazy = 'dynamic'))		#User.signedEvents

	def __init__(self, username, role, pw_hash):
		self.username = username
		self.role = role
		self.pw_hash = pw_hash

	def __repr__(self):
		return self.username

# signedEvents = db.Table('signedEvents',
# 	db.Column('staff_id', db.Integer, db.ForeignKey('User.id')),
# 	db.Column('staff_id', db.Integer, db.ForeignKey('User.id'))
# )

class Event(db.Model):
	__tablename__ = "Event"
	id = db.Column(db.Integer, primary_key=True)
	eventname = db.Column(db.String(24), unique=False, nullable=False)
	date = db.Column(db.String(10), unique=True, nullable=False)
	requester = db.Column(db.String(30), unique=False, nullable=False)
	open = db.Column(db.Boolean, unique=False)
	#attribute
	#TODO: beautify workingStaff
	workingStaff = db.relationship('User', secondary="schedule", backref=db.backref('signedEvents', lazy = 'select'))		#User.signedEvents

	def __init__(self, eventname, date, requester):
		self.eventname = eventname
		self.date = date
		self.requester = requester
		self.open = True

	def __repr__(self):
		return '<Event: {}, Requested by: {}, Staff attending: {}>'.format(self.eventname, self.requester, self.workingStaff)
