import uuid
from functools import wraps
import jwt
from flask import Flask, jsonify, request, make_response, send_file, redirect, render_template, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import set_access_cookies
from datetime import datetime, timedelta
from io import BytesIO
import validators
# SUBMISSION BY ANIRUDH WALIA 19BCS6127 FOR NBYULA 
# PROJECT NAME - SCHDL
# I HAVE USED FLASK-SQL-ALCHEMY TO HANDLE MY DATABASE 
# AND JWT FOR AUTHORIZATION
app = Flask(__name__)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'ajsuwUHUHSkjskw'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/aniru/PycharmProjects/appointment_scheduler/main_database.sqlite3'

db = SQLAlchemy(app)


# the database model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(150), unique=True)
    employee_id = db.Column(db.String(150), unique=True)
    name = db.Column(db.String(50))
    username = db.Column(db.String(20), unique=True)
    email = db.Column(db.String(40))
    password = db.Column(db.String(150))
    admin = db.Column(db.Boolean)
    department = db.Column(db.String(40))


class Meeting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    creators_public_id = db.Column(db.String(150))
    guest_employee_id = db.Column(db.String(150))
    link = db.Column(db.String(150))
    creator = db.Column(db.String(50))
    datee = db.Column(db.DateTime)
    slot = db.Column(db.String(30))
    guest = db.Column(db.String(50))
    title = db.Column(db.String(40))
    agenda = db.Column(db.String(250))
    department = db.Column(db.String(40))
    done = db.Column(db.Boolean)


class Schedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(150))
    employee_id = db.Column(db.String(150))
    name = db.Column(db.String(50))
    username = db.Column(db.String(20))
    email = db.Column(db.String(40))
    department = db.Column(db.String(40))
    datee = db.Column(db.DateTime)
    slot_8to9 = db.Column(db.Boolean)
    slot_9to10 = db.Column(db.Boolean)
    slot_10to11 = db.Column(db.Boolean)
    slot_11to12 = db.Column(db.Boolean)
    slot_12to13 = db.Column(db.Boolean)
    slot_13to14 = db.Column(db.Boolean)
    slot_14to15 = db.Column(db.Boolean)
    slot_15to16 = db.Column(db.Boolean)
    slot_16to17 = db.Column(db.Boolean)
    slot_17to18 = db.Column(db.Boolean)
    slot_18to19 = db.Column(db.Boolean)
    slot_19to20 = db.Column(db.Boolean)


# the decorator token_required to handle jwt tokens authentication
def token_required(f):
    @wraps(f)
    def token_decorated(*args, **kwargs):
        # token = request.args.get('token')
        token = None
        if 'token' in session:
            token = session['token']
        if not token:
            return jsonify({'message': 'Token is missing'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid'}), 403
        return f(current_user, *args, **kwargs)

    return token_decorated


# this will create the database model before any request
@app.before_first_request
def create_tables():
    db.create_all()
    # hashed_pass = generate_password_hash('1234', method='sha256')
    # admin = User(public_id=str(uuid.uuid4()), name='admin', password=hashed_pass, admin=True, teacher=False,
    #              student=False,
    #              class_id=None)
    # db.session.add(admin)
    db.session.commit()


@app.route('/')  # loads the landing page
def index():
    return render_template('index.html')


# sign up routes also generates a jwt
@app.route('/signuserup', methods=['POST'])
def signup():
    fullname = request.form.get('fullname')
    employee_id = request.form.get('employee_id')
    email = request.form.get('email')
    username = request.form.get('username')
    password = request.form.get('pass')
    re_password = request.form.get('repeat-pass')

    if password == re_password:
        hashed_pass = generate_password_hash(password, method='sha256')
        public_id = str(uuid.uuid4())
        new_schdl = Schedule(public_id=public_id, datee=datetime.utcnow())
        new_user = User(public_id=public_id, employee_id=employee_id, name=fullname, password=hashed_pass,
                        email=email, username=username)
        db.session.add(new_user)
        db.session.add(new_schdl)
        db.session.commit()
        token = jwt.encode(
            {'public_id': public_id, 'user': username, 'exp': datetime.utcnow() + timedelta(minutes=300)},
            app.config['SECRET_KEY'])
        session['username'] = username
        session['token'] = token

        return jsonify({'token': token}) and redirect('/home')
    else:
        return redirect('/')


# sign in route also generates a jwt
@app.route('/signinuser', methods=['POST'])
def signin():
    username = request.form.get('username')
    password = request.form.get('pass')

    user = User.query.filter_by(username=username).first()

    if not user:
        return render_template('index.html')

    if check_password_hash(user.password, password):
        token = jwt.encode(
            {'public_id': user.public_id, 'user': username, 'exp': datetime.utcnow() + timedelta(minutes=300)},
            app.config['SECRET_KEY'])
        session['username'] = user.username
        session['token'] = token

        return jsonify({'token': token}) and redirect('/home')
    return render_template('index.html')


# renders the home page
@app.route('/home', methods=['GET'])
@token_required
def home(current_user):
    name = current_user.name
    n = name.split(" ")
    fname = n[0]
    sname = "_"
    if len(n) > 1:
        sname = n[1]
    email = current_user.email
    employee_id = current_user.employee_id
    username = current_user.username
    department = current_user.department
    password = current_user.password
    listt = [name, email, employee_id, username, department, password]
    val = User.query.filter(User.public_id != current_user.public_id).all()
    print(type(val))
    dic = dict()

    schdl = Schedule.query.filter_by(public_id=current_user.public_id).first()
    hh = [schdl.slot_8to9, schdl.slot_9to10, schdl.slot_10to11, schdl.slot_11to12, schdl.slot_12to13,
          schdl.slot_13to14, schdl.slot_14to15, schdl.slot_15to16, schdl.slot_16to17, schdl.slot_17to18,
          schdl.slot_18to19, schdl.slot_19to20,
          ]
    ch = []
    for v in val:
        dic['name'] = name
        dic['employee_id'] = employee_id
        dic['email'] = email
        dic['department'] = department
        schdl = Schedule.query.filter_by(public_id=v.public_id).first()
        hhh = [schdl.slot_8to9, schdl.slot_9to10, schdl.slot_10to11, schdl.slot_11to12, schdl.slot_12to13,
               schdl.slot_13to14, schdl.slot_14to15, schdl.slot_15to16, schdl.slot_16to17, schdl.slot_17to18,
               schdl.slot_18to19, schdl.slot_19to20,
               ]
        dic['list'] = hhh

    for h in hh:
        if h:
            ch.append("checked")
        else:
            ch.append("")
    meets = Meeting.query.filter(((Meeting.creators_public_id == current_user.public_id) | (
            Meeting.guest_employee_id == current_user.employee_id)) & (Meeting.done == False)).all()
    dj = dict()

    for m in meets:
        dj['title'] = m.title
        dj['agenda'] = m.agenda
        dj['guest'] = m.guest
        dj['creator'] = m.creator
        dj['department'] = m.department
        dj['slot'] = m.slot
        dj['date'] = str(m.datee.strftime('%d/%m/%Y'))
        dj['guest-id'] = m.guest_employee_id
        dj['done'] = m.done
        dj['link'] = m.link

    print(dj)
    return render_template('home.html', list=listt, fname=fname, sname=sname, val=val, dic=dic, r=ch, dj=meets)


# renders the modal that shows the schedule of other users
@app.route('/home/showsched/<public_id>', methods=['GET', 'POST'])
@token_required
def showsched(current_user, public_id):
    name = current_user.name
    n = name.split(" ")
    fname = n[0]
    sname = "_"
    if len(n) > 1:
        sname = n[1]
    email = current_user.email
    employee_id = current_user.employee_id
    username = current_user.username
    department = current_user.department
    password = current_user.password
    listt = [name, email, employee_id, username, department, password]
    val = User.query.filter(User.public_id != current_user.public_id).all()
    print(type(val))
    dic = dict()

    schdl = Schedule.query.filter_by(public_id=public_id).first()
    hh = [schdl.slot_8to9, schdl.slot_9to10, schdl.slot_10to11, schdl.slot_11to12, schdl.slot_12to13,
          schdl.slot_13to14, schdl.slot_14to15, schdl.slot_15to16, schdl.slot_16to17, schdl.slot_17to18,
          schdl.slot_18to19, schdl.slot_19to20,
          ]
    ch = []
    for h in hh:
        if h:
            ch.append("checked")
        else:
            ch.append("")
    return render_template('modal.html', list=listt, fname=fname, sname=sname, val=val, dic=dic, r=ch,
                           show_schedule_modal=True)


# renders the modal used for scheduling a meeting
@app.route('/home/makeappointment/<public_id>', methods=['GET', 'POST'])
@token_required
def makesched(current_user, public_id):
    name = current_user.name
    n = name.split(" ")
    fname = n[0]
    sname = "_"
    if len(n) > 1:
        sname = n[1]
    email = current_user.email
    employee_id = current_user.employee_id
    username = current_user.username
    department = current_user.department
    password = current_user.password
    listt = [name, email, employee_id, username, department, password]
    val = User.query.filter(User.public_id != current_user.public_id).all()
    print(type(val))
    dic = dict()

    schdl = Schedule.query.filter_by(public_id=public_id).first()
    hh = [schdl.slot_8to9, schdl.slot_9to10, schdl.slot_10to11, schdl.slot_11to12, schdl.slot_12to13,
          schdl.slot_13to14, schdl.slot_14to15, schdl.slot_15to16, schdl.slot_16to17, schdl.slot_17to18,
          schdl.slot_18to19, schdl.slot_19to20,
          ]
    ch = []
    new_list = Schedule.query.filter_by(public_id=public_id).order_by(Schedule.id.desc()).limit(6).distinct().all()
    date_lis = []
    day_lis = []
    a8to9 = []
    a9to10 = []
    a10to11 = []
    a11to12 = []
    a12to13 = []
    a13to14 = []
    a14to15 = []
    a15to16 = []
    a16to17 = []
    a17to18 = []
    a18to19 = []
    a19to20 = []
    o = ["MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY", "SUNDAY"]
    for p in new_list:
        day_lis.append(o[p.datee.weekday()])
        date_lis.append(str(p.datee.strftime('%d/%m/%Y')))
        a8to9.append(p.slot_8to9)
        a9to10.append(p.slot_9to10)
        a10to11.append(p.slot_10to11)
        a11to12.append(p.slot_11to12)
        a12to13.append(p.slot_12to13)
        a13to14.append(p.slot_13to14)
        a14to15.append(p.slot_14to15)
        a15to16.append(p.slot_15to16)
        a16to17.append(p.slot_16to17)
        a17to18.append(p.slot_17to18)
        a18to19.append(p.slot_18to19)
        a19to20.append(p.slot_19to20)
    new_listt = Schedule.query.filter_by(public_id=current_user.public_id).order_by(Schedule.id.desc()).limit(
        6).distinct().all()
    date_list = []
    id_list = []
    day_list = []
    a8to9t = []
    a9to10t = []
    a10to11t = []
    a11to12t = []
    a12to13t = []
    a13to14t = []
    a14to15t = []
    a15to16t = []
    a16to17t = []
    a17to18t = []
    a18to19t = []
    a19to20t = []
    for p in new_listt:
        id_list.append(p.id)
        day_list.append(o[p.datee.weekday()])
        date_list.append(str(p.datee.strftime('%d/%m/%Y')))
        a8to9t.append(p.slot_8to9)
        a9to10t.append(p.slot_9to10)
        a10to11t.append(p.slot_10to11)
        a11to12t.append(p.slot_11to12)
        a12to13t.append(p.slot_12to13)
        a13to14t.append(p.slot_13to14)
        a14to15t.append(p.slot_14to15)
        a15to16t.append(p.slot_15to16)
        a16to17t.append(p.slot_16to17)
        a17to18t.append(p.slot_17to18)
        a18to19t.append(p.slot_18to19)
        a19to20t.append(p.slot_19to20)
    print(date_lis)
    for v in range(0, 6):
        if a8to9[v] == True and a8to9t[v] == True:
            a8to9[v] = True
        else:
            a8to9[v] = False
    x = [a8to9, a9to10, a10to11, a11to12, a12to13,
         a13to14, a14to15, a15to16, a16to17, a17to18,
         a18to19, a19to20]
    xx = [a8to9t, a9to10t, a10to11t, a11to12t, a12to13t,
          a13to14t, a14to15t, a15to16t, a16to17t, a17to18t,
          a18to19t, a19to20t]
    for (v, l) in zip(x, xx):
        for j in range(0, 5):
            if v[j] == True and l[j] == True:
                v[j] = True
            else:
                v[j] = False

    for h in hh:
        if h:
            ch.append("checked")
        else:
            ch.append("")

    return render_template('modal2.html', list=listt, fname=fname, sname=sname, val=val, dic=dic, r=ch,
                           show_schedule_modal=True, day=day_lis, date=date_lis, a8=a8to9, a9=a9to10, a10=a10to11,
                           a11=a11to12,
                           a12=a12to13, a13=a13to14, a14=a14to15, a15=a15to16, a16=a16to17, a17=a17to18, a18=a18to19,
                           a19=a19to20, namee=schdl.name, pub=public_id, idd=id_list, dept=schdl.department,
                           emp_id=schdl.employee_id)


# saves the meeting info in the db
@app.route('/savemeeting/<public_id>', methods=['POST'])
@token_required
def savemeeting(current_user, public_id):
    date_val = request.form.get('date')
    time_slot_val = request.form.get('time')
    creator_name = current_user.name
    guest_name = request.form.get('name')
    title = request.form.get('title')
    agenda = request.form.get('agenda')
    link = request.form.get('link')
    guest_id = request.form.get('emp_id')
    time_slot_val = int(time_slot_val)
    jid = ""
    for i in date_val:
        if i.isnumeric():
            jid = jid + i
    jid = int(jid)
    print(jid)

    if time_slot_val >= 12:
        k = time_slot_val - 12
        slot = str(k) + " P.M TO " + str(k + 1) + " P.M"
    elif time_slot_val == 11:
        slot = "11 A.M TO 12 P.M"
    else:
        slot = str(time_slot_val) + " A.M TO " + str(time_slot_val + 1) + " A.M"
    print(date_val, time_slot_val, slot)
    val = Schedule.query.filter_by(id=jid).first()
    if time_slot_val == 8:
        val.slot_8to9 = False
    elif time_slot_val == 9:
        val.slot_9to10 = False
    elif time_slot_val == 10:
        val.slot_10to11 = False
    elif time_slot_val == 11:
        val.slot_11to12 = False
    elif time_slot_val == 12:
        val.slot_12to13 = False
    elif time_slot_val == 13:
        val.slot_13to14 = False
    elif time_slot_val == 14:
        val.slot_14to15 = False
    elif time_slot_val == 15:
        val.slot_15to16 = False
    elif time_slot_val == 16:
        val.slot_16to17 = False
    elif time_slot_val == 17:
        val.slot_17to18 = False
    elif time_slot_val == 18:
        val.slot_18to19 = False
    elif time_slot_val == 19:
        val.slot_19to20 = False

    new_meet = Meeting(creators_public_id=current_user.public_id, guest_employee_id=guest_id, creator=current_user.name,
                       guest=guest_name, title=title, agenda=agenda, link=link, slot=slot,
                       department=current_user.department, datee=val.datee, done=False)
    db.session.add(new_meet)
    db.session.commit()
    return redirect('/home/meetingdone')


# when a meeting is scheduled it redirects the confirmed message
@app.route('/home/meetingdone')
@token_required
def meetingdone(current_user):
    return render_template('suc.html'), {"Refresh": "2; url=/home"}


# route handling changes in a users profile
@app.route('/updateuserprofile', methods=['POST', 'PUT'])
@token_required
def updateuser(current_user):
    fullname = request.form.get('fullname')
    employee_id = request.form.get('employee_id')
    email = request.form.get('email')
    username = request.form.get('username')
    department = request.form.get('department')
    print(fullname)
    user = User.query.filter_by(public_id=current_user.public_id).first()
    if not user:
        return jsonify({'message': 'no user found'})
    user.name = fullname
    user.employee_id = employee_id
    user.email = email
    user.username = username
    user.department = department
    # user.password = generate_password_hash(update_data['password'], method='sha256')
    db.session.commit()
    return redirect('/home')


# redirected if password was wrong while changing
@app.route('/home/passnotsame', methods=['GET'])
@token_required
def homepassnotsame(current_user):
    name = current_user.name
    n = name.split(" ")
    print(name)
    print(n)
    fname = n[0]
    sname = "_"
    if len(n) > 1:
        sname = n[1]
    email = current_user.email
    employee_id = current_user.employee_id
    username = current_user.username
    department = current_user.department
    password = current_user.password
    listt = [name, email, employee_id, username, department, password]
    return render_template('home.html', list=listt, fname=fname, sname=sname, msg="NEW PASSWORDS DON'T MATCH")


# redirected if password was wrong while changing
@app.route('/home/oldpasswrong', methods=['GET'])
@token_required
def homeoldpasswrong(current_user):
    name = current_user.name
    n = name.split(" ")
    print(name)
    print(n)
    fname = n[0]
    sname = "_"
    if len(n) > 1:
        sname = n[1]
    email = current_user.email
    employee_id = current_user.employee_id
    username = current_user.username
    department = current_user.department
    password = current_user.password
    listt = [name, email, employee_id, username, department, password]
    return render_template('home.html', list=listt, fname=fname, sname=sname, msg="OLD PASSWORD IS WRONG")


# route to handle changing passwords
@app.route('/changepassword', methods=['POST', 'PUT'])
@token_required
def changepass(current_user):
    user = User.query.filter_by(public_id=current_user.public_id).first()
    password = request.form.get('pass')
    new_pass = request.form.get('new_pass')
    re_new_pass = request.form.get('re_new_pass')

    if not user:
        return jsonify({'message': 'no user found'})
    if check_password_hash(user.password, password):
        if new_pass == re_new_pass:
            hashed_password = generate_password_hash(new_pass, method='sha256')
            user.password = hashed_password
            db.session.commit()
            return redirect('/home')
        else:
            return redirect('/home/passnotsame')
    else:
        return redirect('home/oldpasswrong')


# this route updates your time schedule
@app.route('/updateschedule', methods=['POST', 'PUT'])
@token_required
def update_sched(current_user):
    user = User.query.filter_by(public_id=current_user.public_id).first()
    if not user:
        return jsonify({'message': 'no user found'})
    w1 = request.form.get('1')
    w2 = request.form.get('2')
    w3 = request.form.get('3')
    w4 = request.form.get('4')
    w5 = request.form.get('5')
    w6 = request.form.get('6')
    w7 = request.form.get('7')
    w8 = request.form.get('8')
    w9 = request.form.get('9')
    w10 = request.form.get('10')
    w11 = request.form.get('11')
    w12 = request.form.get('12')
    parchi = [w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12]
    schdl = Schedule.query.filter_by(public_id=current_user.public_id).first()
    vl = []
    for p in parchi:
        if p is None:
            vl.append(False)
        else:
            vl.append(True)
    schdl.public_id = current_user.public_id
    schdl.employee_id = current_user.employee_id
    schdl.name = current_user.name
    schdl.username = current_user.username
    schdl.email = current_user.email
    schdl.department = current_user.department
    schdl.datee = datetime.utcnow()
    schdl.slot_8to9 = vl[0]
    schdl.slot_9to10 = vl[1]
    schdl.slot_10to11 = vl[2]
    schdl.slot_11to12 = vl[3]
    schdl.slot_12to13 = vl[4]
    schdl.slot_13to14 = vl[5]
    schdl.slot_14to15 = vl[6]
    schdl.slot_15to16 = vl[7]
    schdl.slot_16to17 = vl[8]
    schdl.slot_17to18 = vl[9]
    schdl.slot_18to19 = vl[10]
    schdl.slot_19to20 = vl[11]
    print(parchi)
    print(vl)
    db.session.commit()
    for i in range(1, 6):
        new_user = Schedule(public_id=current_user.public_id, employee_id=current_user.employee_id,
                            name=current_user.name,
                            email=current_user.email, username=current_user.username,
                            department=current_user.department,
                            datee=datetime.utcnow() + timedelta(days=i),
                            slot_8to9=vl[0],
                            slot_9to10=vl[1],
                            slot_10to11=vl[2],
                            slot_11to12=vl[3],
                            slot_12to13=vl[4],
                            slot_13to14=vl[5],
                            slot_14to15=vl[6],
                            slot_15to16=vl[7],
                            slot_16to17=vl[8],
                            slot_17to18=vl[9],
                            slot_18to19=vl[10],
                            slot_19to20=vl[11],
                            )
        db.session.add(new_user)
        print(parchi)
        print(vl)
        db.session.commit()

    return redirect('/home')


# when the meeting is completed mark it as done
@app.route('/done/<meeting_id>', methods=['GET', 'POST'])
@token_required
def donee(current_user, meeting_id):
    qur = Meeting.query.filter_by(id=meeting_id).first()
    qur.done = True
    db.session.commit()
    return redirect('/home')


# the logout route
@app.route('/logout')
@token_required
def logout(current_user):
    session['token'] = ""
    session['name'] = ""
    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)
