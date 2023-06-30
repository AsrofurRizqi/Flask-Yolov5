# import libraries
from urllib.request import urlopen
from dotenv import load_dotenv
import pymysql
pymysql.install_as_MySQLdb()
from io import StringIO
from flask import Flask, request, render_template, make_response, send_file, after_this_request
import json
from flask_restx import Resource, Api, reqparse
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, send, emit, join_room, leave_room

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename
import datetime as dt
from datetime import timedelta, datetime, date
from functools import wraps
import csv

import os
import shutil
import subprocess
import cloudinary
from cloudinary.uploader import upload
from cloudinary.utils import cloudinary_url

# Flask Configuration.
load_dotenv()
app = Flask(__name__, template_folder='web')
api = Api(app, version='1.0', title='Drown API', description='Drown API Documentation')
mail= Mail(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# JWT Configuration.
SECRET_KEY = os.getenv('SECRET_KEY')
ISSUER = os.getenv('ISSUER')
AUDIENCE_MOBILE = os.getenv('AUDIENCE_MOBILE')

import jwt

# Cloudinary Configuration.
cloudinary.config(
	cloud_name = os.getenv('CLOUDINARY_CLOUD_NAME'),
	api_key = os.getenv('CLOUDINARY_API_KEY'),
	api_secret = os.getenv('CLOUDINARY_API_SECRET'),
	secure = True,
)

upload_options = {
	'folder': 'drown',
}

# Email Configuration.
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

# File Upload Configuration.
UPLOAD_FOLDER = './public/images'
VIDEO_FOLDER = './public/videos'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', "mp4"}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['VIDEO_FOLDER'] = VIDEO_FOLDER

# Database Configuration.
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv('DATABASE_URL')
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
db = SQLAlchemy(app)

# Database Class Model.
class User(db.Model):
	__tablename__ = "user"
	id		= db.Column(db.Integer(), primary_key=True, nullable=False)
	email	= db.Column(db.String(32), unique=True, nullable=False)
	name	= db.Column(db.String(64), nullable=False)
	password	= db.Column(db.String(256), nullable=False)
	verified	= db.Column(db.Boolean(), nullable=False, default=False)
	profile = db.Column(db.String(500), nullable=False, default=False)

class Artickel(db.Model):
	__tablename__ = "artikel"
	id = db.Column(db.Integer(), primary_key=True, nullable=False)
	judul = db.Column(db.String(256), nullable=False)
	deskripsi = db.Column(db.Text(), nullable=False)
	gambar = db.Column(db.String(256), nullable=False)
	tanggal = db.Column(db.DateTime)
	def serialize(self):
		return {
			'id': str(self.id),
			'judul': self.judul,
			'deskripsi': self.deskripsi,
			'gambar': self.gambar,
			'tanggal': str(self.tanggal)
		}

class Aktifitas(db.Model):
	__tablename__ = "aktifitas"
	id = db.Column(db.Integer(), primary_key=True, nullable=False)
	timestamp = db.Column(db.DateTime)
	perenang = db.Column(db.Integer(), nullable=False)
	tenggelam = db.Column(db.Integer(), nullable=False)
	tanggal = db.Column(db.Date(), nullable=False)
	status = db.Column(db.Boolean(), nullable=False)
	def serializeB(self):
		return {
			'id': str(self.id),
			'timestamp': str(self.timestamp),
			'perenang': str(self.perenang),
			'tenggelam': str(self.tenggelam),
			'tanggal': str(self.tanggal),
			'status': self.status
		}

class Notifications(db.Model):
	__tablename__ = "notifications"
	id = db.Column(db.Integer(), primary_key=True, nullable=False)
	user_id = db.Column(db.Integer(), nullable=False)
	message = db.Column(db.String(256), nullable=False)
	timestamp = db.Column(db.DateTime)
	def serializeC(self):
		return {
			'id': str(self.id),
			'user_id': str(self.user_id),
			'message': self.message,
			'timestamp': str(self.timestamp),
		}

#register
parser4SignUp = reqparse.RequestParser()
parser4SignUp.add_argument('email', type=str, location='json', 
	required=True, help='Email Address')
parser4SignUp.add_argument('name', type=str, location='json', 
	required=True, help='Fullname')
parser4SignUp.add_argument('password', type=str, location='json', 
	required=True, help='Password')
parser4SignUp.add_argument('re_password', type=str, location='json', 
	required=True, help='Retype Password')

@api.route('/auth/signup')
class Registration(Resource):
	@api.expect(parser4SignUp)
	def post(self):
		args 		= parser4SignUp.parse_args()
		email 		= args['email']
		name 		= args['name']
		password 	= args['password']
		rePassword 	= args['re_password']

		if password != rePassword:
			return {
				'message': 'Password is not the same!'
			}, 400 # HTTP Status Code for Bad Request.

		user = db.session.execute(db.select(User).filter_by(email=email)).first()
		if user:
			return {
				'message': 'This email address has been used!'
			}, 409 # HTTP Status Code for "Conflict".
		
		try:
			user 			= User() # User instantiation.
			user.email 		= email
			user.name 		= name
			user.password 	= generate_password_hash(password)
			user.profile 	= 'https://res.cloudinary.com/dkxt6mlnh/image/upload/v1682927959/drown/images-removebg-preview_nmbyo7.png'
		
			db.session.add(user)
			db.session.commit()

			ids = db.session.execute(db.select(User).filter_by(email=email)).first()
			id = ids[0]
			payload = {
				'user_id': id.id,
				'email': email,
				'aud': AUDIENCE_MOBILE,
				'iss': ISSUER,
				'iat': datetime.utcnow(),
				'exp': datetime.utcnow() + timedelta(hours=2)
			}
			verify_token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

			url = f"https://api-drown.up.railway.app/auth/verify?token={verify_token}"
			msg = Message('Email Verification', sender = os.getenv('MAIL_USERNAME'), recipients = [email])
			msg.html = render_template('verifemail.html', name=name, url=url)
			mail.send(msg)

			return {
				'message': 'Successful Registered! Please check your email to verify your account.'
			}, 201 # HTTP Status Code for "Created".
		
		except Exception as err:
			return {
				'message': str(err)
			}, 500

#login
parser4SignIn = reqparse.RequestParser()
parser4SignIn.add_argument('email', type=str, location='json', 
	required=True, help='Email Address')
parser4SignIn.add_argument('password', type=str, location='json', 
	required=True, help='Password')

@api.route('/auth/signin')
class LogIn(Resource):
	@api.expect(parser4SignIn)
	def post(self):
		args 		= parser4SignIn.parse_args()
		email 		= args['email']
		password 	= args['password']
		
		try:
			if not email or not password:
				return {
					'message': 'Please type email and password!'
				}, 400

			user = db.session.execute(db.select(User).filter_by(email=email)).first()
			if not user:
				return {
					'message': 'Wrong email!'
				}, 400
			else:
				user = user[0] # Unpack the array

			if user.verified == False:
				return {
					'message': 'Please verify your email first!'
				}, 400

			if check_password_hash(user.password, password):
				payload = {
					'user_id': user.id,
					'email': user.email,
					'aud': AUDIENCE_MOBILE,
					'iss': ISSUER,
					'iat': datetime.utcnow(),
					'exp': datetime.utcnow() + timedelta(days=7)
				}
				token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
				return {
					'message': 'Successful Logged In!',
					'email': user.email,
					'name' : user.name,
					'profile': user.profile,
					'token': token
				}, 200
			else:
				return {'message': 'Wrong email or password!'}, 400
		
		except Exception as err:
			return {
				'message': str(err)
			}, 500

#token cek
parser4Basic = reqparse.RequestParser()
parser4Basic.add_argument('Authorization', type=str, location='headers', required=True)

@api.route('/auth/token-check')
class BasicAuth(Resource):
	@api.expect(parser4Basic)
	def get(self):
		args 		= parser4Basic.parse_args()
		basicAuth 	= args['Authorization']
		if args['Authorization'].split(' ')[0] != 'Bearer':
			return {
				'message': 'Token is invalid!'
			}, 400
		token = basicAuth.split(' ')[1]
		try:
			payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)
			user = db.session.execute(db.select(User).filter_by(id=payload["user_id"])).first()
			expiration_date = dt.datetime.fromtimestamp(payload['exp'])
			if user:
				user = user[0]
				return {
					'message': 'Success Token Check!',
					'nama': user.name,
					'email': user.email,
					'verified': user.verified,
					'profile': user.profile,
					'expired': expiration_date.strftime("%d %B %Y %H:%M:%S")
				}, 200
			else:
				return {
					'message': 'Token is invalid!'
				}, 400
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Token is invalid!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500

parserToken = reqparse.RequestParser()
parserToken.add_argument('token', type=str, location='args', required=True)

@api.route('/auth/verify')
class Verify(Resource):
	@api.expect(parserToken)
	def get(self):
		args = parserToken.parse_args()
		if args is None:
			return {
				'message': 'Token is invalid!'
			}, 400
		token = args['token']

		try:
			payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)
			user = db.session.execute(db.select(User).filter_by(email=payload['email'])).first()

			if user:
				user = user[0]
				if user.verified == True:
					return make_response(render_template('veriffailed.html'),200, {'Content-Type': 'text/html'})
				user.verified = True
				db.session.commit()
				return make_response(render_template('verif.html'),200, {'Content-Type': 'text/html'})
			else:
				return {
					'message': 'User not found!'
				}, 404
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Invalid Token!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500

#allowed file
def allowed_file(filename):
	return '.' in filename and \
		filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

#profile
parserProfile = reqparse.RequestParser()
parserProfile.add_argument('Authorization', type=str, location='headers', required=True)
parserProfile.add_argument('name', type=str, location='form', required=False)
parserProfile.add_argument('email', type=str, location='form', required=False)
parserProfile.add_argument('profile', type=FileStorage, location='files', required=False)

@api.route('/user/profile')
class Profile(Resource):
	@api.expect(parserProfile)
	def put(self):
		args = parserProfile.parse_args()
		bearerAuth = args['Authorization']
		name = args['name']
		email = args['email']
		profile = args['profile']

		if args['Authorization'].split(' ')[0] != 'Bearer':
			return {
				'message': 'Authorization type is not Bearer!'
			}, 400
		token = bearerAuth.split(' ')[1]

		try:
			payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)
			user = db.session.execute(db.select(User).filter_by(id=payload['user_id'])).first()

			if user:
				user = user[0]
				if profile and allowed_file(profile.filename):
					filename = secure_filename(profile.filename)
					profile.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
					try:
						upload_result = upload(os.path.join(app.config['UPLOAD_FOLDER'], filename), **upload_options)
						image = upload_result['secure_url']
						os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))

					except Exception as err:
						return {
							'message': str(err)
						}, 500
						
				if name is not None and name != '':
					user.name = name
				if email is not None and email != '':
					user.email = email
				if profile is not None and profile != '':
					user.profile = image
				
				db.session.commit()
				return {
					'message': 'Profile updated!'
				}, 200
			else:
				return {
					'message': 'User not found!'
				}, 404
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Invalid Token!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500

#artikel		
parseArtikel = reqparse.RequestParser()
parseArtikel.add_argument('Authorization', type=str, location='headers', required=True)
parseArtikel.add_argument('judul', type=str, location='json', required=True)
parseArtikel.add_argument('deskripsi', type=str, location='json', required=True)
parseArtikel.add_argument('gambar', type=str, location='json', required=True)

@api.route('/data/artikel')
class Artikel(Resource):
	@api.expect(parser4Basic)
	def get(self):
		args = parser4Basic.parse_args()
		bearerAuth = args['Authorization']
		if bearerAuth.split(' ')[0] != 'Bearer':
			return {
				'message': 'Authorization type is not Bearer!'
			}, 400
		token = bearerAuth.split(' ')[1]

		try:
			payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)
			user = db.session.execute(db.select(User).filter_by(id=payload['user_id'])).first()
			if user is None:
				return {
					'message': 'User not found!'
				}, 404
			
			datas = db.session.execute(db.select(Artickel))
			rows = Artickel.query.all()
			datas = [Artickel.serialize(row) for row in rows]
			return {
				'message': 'Success get artikel data!',
				'data': datas
			}, 200
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Invalid Token!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500
		
	@api.expect(parseArtikel)
	def post(self):
		args = parseArtikel.parse_args()
		bearerAuth = args['Authorization']
		judul = args['judul']
		deskripsi = args['deskripsi']
		gambar = args['gambar']

		if judul is None or deskripsi is None or gambar is None:
			return {
				'message': 'Missing data!'
			}, 400
		
		if bearerAuth.split(' ')[0] != 'Bearer':
			return {
				'message': 'Authorization type is not Bearer!'
			}, 400
		token = bearerAuth.split(' ')[1]

		try:
			payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)
			user = db.session.execute(db.select(User).filter_by(id=payload['user_id'])).first()
			if user is None:
				return {
					'message': 'User not found!'
				}, 404
			
			artikel = Artickel()
			artikel.judul = judul
			artikel.deskripsi = deskripsi
			artikel.gambar = gambar
			artikel.tanggal = datetime.utcnow()

			db.session.add(artikel)
			db.session.commit()
			return {
				'message': 'Success add artikel data!'
			}, 200
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400	
		except jwt.InvalidTokenError:
			return {
				'message': 'Invalid Token!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500

@api.route('/data/artikel/<string:id>')
class Artikel(Resource):
	@api.expect(parser4Basic)
	def get(self,id):
		args = parser4Basic.parse_args()
		bearerAuth = args['Authorization']
		if bearerAuth.split(' ')[0] != 'Bearer':
			return {
				'message': 'Authorization type is not Bearer!'
			}, 400
		token = bearerAuth.split(' ')[1]

		try:
			payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)
			user = db.session.execute(db.select(User).filter_by(id=payload['user_id'])).first()
			if user is None:
				return {
					'message': 'User not found!'
				}, 404
			datas = db.session.execute(db.select(Artickel).filter_by(id=id)).first()
			if not datas:
				return {
					'message': 'Artikel not found!'
				}, 404
			else:
				datas = datas[0]
				return {
					'message': 'Success get artikel data by id!',
					'data': {
						'id': datas.id,
						'judul': datas.judul,
						'deskripsi': datas.deskripsi,
						'gambar': datas.gambar,
						'tanggal': str(datas.tanggal)
					}
				}, 200
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Invalid Token!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500

parserLogs = reqparse.RequestParser()
parserLogs.add_argument('Authorization', type=str, location='headers', required=True)

@api.route('/data/logsdata')
class LogsData(Resource,):
	@api.expect(parserLogs)
	def get(self):
		args = parserLogs.parse_args()
		bearerAuth = args['Authorization']
		if args['Authorization'].split(' ')[0] != 'Bearer':
			return {
				'message': 'Authorization type is not Bearer!'
			}, 400
		token = bearerAuth.split(' ')[1]
		
		try:
			payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)

			user = db.session.execute(db.select(User).filter_by(id=payload['user_id'])).first()
			if user is None:
				return {
					'message': 'User not found!'
				}, 404
			
			datas = db.session.execute(db.select(Aktifitas))
			if datas:
				rows = Aktifitas.query.all()
				json_str = [Aktifitas.serializeB(row) for row in reversed(rows)]
				return {
					'message': 'Success get logs data!',
					'datas': json_str
				}, 200
			else:
				return {
					'message': 'Data not inserted yet!'
				}, 404
			
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Invalid Token!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500

@api.route('/data/logsdata/download')
class LogsDataDownload(Resource):
	@api.expect(parserLogs)
	def get(self):
		args = parserLogs.parse_args()
		bearerAuth = args['Authorization']
		if args['Authorization'].split(' ')[0] != 'Bearer':
			return {
				'message': 'Authorization type is not Bearer!'
			}, 400
		token = bearerAuth.split(' ')[1]

		try:
			payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)

			user = db.session.execute(db.select(User).filter_by(id=payload['user_id'])).first()
			if user is None:
				return {
					'message': 'User not found!'
				}, 404
			
			datas = db.session.execute(db.select(Aktifitas))
			if datas:
				rows = Aktifitas.query.all()
				csv_data = StringIO()
				csv_writer = csv.writer(csv_data)
				csv_writer.writerow(['id', 'timestamp', 'perenang', 'tenggelam', 'tanggal'])
				for item in rows:
					csv_writer.writerow([item.id, item.timestamp, item.perenang, item.tenggelam, item.tanggal])

				response = make_response(csv_data.getvalue())
				response.headers['Content-Disposition'] = 'attachment; filename=logsdata.csv'
				response.headers['Content-Type'] = 'text/csv'

				return response
			else:
				return {
					'message': 'Data not inserted yet!'
				}, 404
		
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Invalid Token!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500
		
@api.route('/user/forgotpassword')
class ForgotPassword(Resource):
	@api.expect(parser4Basic)
	def get(self):
		args = parser4Basic.parse_args()
		bearer = args['Authorization']
		if bearer.split(' ')[0] != 'Bearer':
			return {
				'message': 'Authorization type is not Bearer!'
			}, 400
		token = bearer.split(' ')[1]
		try:
			payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)
			user = db.session.execute(db.select(User).filter_by(id=payload['user_id'])).first()
			if user is None:
				return {
					'message': 'User not found!'
				}, 404
			email = user[0].email
			print(email)
			payload = {
				'user_id': payload['user_id'],
				'email': email,
				'aud': AUDIENCE_MOBILE,
				'iss': ISSUER,
				'exp': datetime.utcnow() + timedelta(minutes=30),
			}
			code = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
			url = f'https://api-drown.up.railway.app/user/pagereset?code={code}'
			msg = Message('Forgot Password', sender = os.getenv('MAIL_USERNAME'), recipients=[email])
			msg.html = render_template('forgotpassword.html', url=url , name=user[0].name)
			mail.send(msg)
			return {
				'message': 'Success send email forgot password!',
			}, 200
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Invalid Token!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500

parserLupa = reqparse.RequestParser()
parserLupa.add_argument('email', type=str, location='json', required=True)
@api.route('/user/lupa')
class LupaPassword(Resource):
	@api.expect(parserLupa)
	def post(self):
		args = parserLupa.parse_args()
		email = args['email']
		if email is None:
			return {
				'message': 'Email is required!'
			}, 400
		try:
			user = db.session.execute(db.select(User).filter_by(email=email)).first()
			if not user:
				return {
					'message': 'User not found!'
				}, 404
			payload = {
				'user_id': user[0].id,
				'email': email,
				'aud': AUDIENCE_MOBILE,
				'iss': ISSUER,
				'exp': datetime.utcnow() + timedelta(minutes=30),
			}
			code = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
			url = f'https://api-drown.up.railway.app/user/pagereset?code={code}'
			msg = Message('Forgot Password', sender = os.getenv('MAIL_USERNAME'), recipients=[email])
			msg.html = render_template('forgotpassword.html', url=url , name=user[0].name)
			mail.send(msg)
			return {
				'message': 'Success send email forgot password!',
			}, 200
		except Exception as err:
			return {
				'message': str(err)
			}, 500

parserCode = reqparse.RequestParser()
parserCode.add_argument('code', type=str, location='args', required=True)
@api.route('/user/pagereset')
class PageResetPassword(Resource):
	def get (self):
		try:
			args = parserCode.parse_args()
			code = args['code']
			payload = jwt.decode(code, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)
			user = db.session.execute(db.select(User).filter_by(id=payload['user_id'])).first()
			if user is None:
				return {
					'message': 'User not found!'
				}, 404
			return make_response(render_template('resetpassword.html', name=user[0].name, code=code))
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Invalid Token!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500

#resetpassword
parserResetPassword = reqparse.RequestParser()
parserResetPassword.add_argument('code', type=str, location='form', required=True)
parserResetPassword.add_argument('password', type=str, location='form', required=True)
parserResetPassword.add_argument('confirm_password', type=str, location='form', required=True)

@api.route('/user/resetpassword')
class ResetPassword(Resource):
	@api.expect(parserResetPassword)
	def post(self):
		args = parserResetPassword.parse_args()
		code = args['code']
		if code is None:
			return {
				'message': 'Code is required!'
			}, 401
		password = args['password']
		confirm_password = args['confirm_password']
		if password != confirm_password:
			return {
				'message': 'Password and confirm password not match!'
			}, 400

		try:
			payload = jwt.decode(code, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)
			email = payload['email']
			user = db.session.execute(db.select(User).filter_by(email=payload['email'])).first()
			if user is None:
				return {
					'message': 'User not found!'
				}, 404
			user[0].password = generate_password_hash(password)
			db.session.commit()
			return make_response(render_template('resetsuccess.html'))
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Invalid Token!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500

#upload video
parserVideo = reqparse.RequestParser()
parserVideo.add_argument('Authorization', type=str, location='headers', required=True)
parserVideo.add_argument('video_url', type=str, location='json', required=True, help='Video URL : RTSP, RTMP, HTTP, HTTPS')

@api.route('/predict/video')
class UploadVideo(Resource):
	@api.expect(parserVideo)
	def post(self):
		args = parserVideo.parse_args()
		bearerAuth = args['Authorization']
		video = args['video_url']
		if bearerAuth.split(' ')[0] != 'Bearer':
			return {
				'message': 'Bearer token not found!'
			}, 401
		if video is None:
			return {
				'message': 'Video is required!'
			}, 400
		token = bearerAuth.split(' ')[1]
		try:
			payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)
			user = db.session.execute(db.select(User).filter_by(id=payload['user_id'])).first()
			if user is None:
				return {
					'message': 'User not found!'
				}, 404
			if video is None:
				return {
					'message': 'Video url is required!'
				}, 400
			# checking valid url
			try:
				urlopen(video)
			except Exception as err:
				return {
					'message': "Invalid video url!",
					'error': str(err)
				}, 400
			# run subprocess predict
			subprocess.run(['python3', 'detect.py', '--source', f'{video}', '--weights', './models_custom/best_v5n.onsnx', '--nosave', '--exist-ok', '--userid', f'{user[0].id}'])
			print('success predict')

			return {
				'message': 'success send data'
			}
			
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Invalid Token!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500

parserNotif = reqparse.RequestParser()
parserNotif.add_argument('Authorization', type=str, location='headers', required=True)
@api.route('/user/notifications')
class Notif(Resource):
	@api.expect(parserNotif)
	def get(self):
		args = parserNotif.parse_args()
		bearerAuth = args['Authorization']
		if bearerAuth.split(' ')[0] != 'Bearer':
			return {
				'message': 'Bearer token not found!'
			}, 401
		token = bearerAuth.split(' ')[1]
		try:
			payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)
			
			#get one newest notification
			notif = db.session.execute(db.select(Notifications).filter_by(user_id = payload["user_id"]).order_by(Notifications.timestamp.desc()))
			if not notif:
				return {
					'message': 'Notification not found!'
				}, 404
			rows = Notifications.query.filter_by(user_id = payload["user_id"]).order_by(Notifications.timestamp.desc()).all()
			datas = [Notifications.serializeC(row) for row in reversed(rows)]
			return {
				'message': 'success get notification',
				'data': datas
			}
		
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Invalid Token!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500

@api.route('/stream')
class Stream(Resource):
	def get(self):
		try:
			# run subprocess predict
			subprocess.run(['python3', 'detect.py', '--source', '0', '--weights', './models_custom/best_v5n.onnx', '--name', 'stream'])

			return {
				'message': 'success'
			}
			
		except Exception as err:
			return {
				'message': str(err)
			}, 500

@api.route('/stream/page')
class PageStream(Resource):
	def get(self):
		try:
			return make_response(render_template('index.html'))
		except Exception as err:
			return {
				'message': str(err)
			}, 500

@api.route('/stream/returndata')
class StreamReturnData(Resource):
	def get(self):
		try:
			#get predict data
			data = request.args.get('data')
			location = os.path.join('runs/detect', data)
			try:
				return send_file(location, attachment_filename=data)
			except Exception as err:
				return {
					'message': str(err)
				}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500
		
if __name__ == '__main__':
    app.run(ssl_context='adhoc', debug=True)