const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const cookieParser = require('cookie-parser'); 
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '10mb' })); 
app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true,
}));
app.use(cookieParser());

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  reset_password_token: { type: String },
  reset_password_expiration: Date,
});

const eventSchema = new mongoose.Schema({
  place: { type: String, required: true },
  eventname: { type: String, required: true },
  participationNumber: { type: Number, required: true },
  duration: { type: String, required: true },
  address: { type: String, required: true },
  image: { type: String },
  startTime:{ type: String, required: true },
  endTime: { type: String, required: true},
  seatsTaken: { type: Number, default: 0 },
  attendees: [
    {
      name: { type: String, required: true },
      mobile: { type: String, required: true },
      seats: { type: Number, required: true },
    }
  ],
});


const User = mongoose.model('User', userSchema);
const Event = mongoose.model('Event', eventSchema);

const generateToken = (res, userId) => {
  const token = jwt.sign({ userId }, process.env.JWT_SECRET_KEY, {
    expiresIn: "5d"
  });

  res.cookie("token", token, {
    httpOnly: true,
    sameSite: "strict",
    maxAge: 5 * 24 * 60 * 60 * 1000
  });
};

app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;
  if (password.length < 8) {
    return res.status(400).json({ message: 'Password must be at least 8 characters' });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();

    generateToken(res, newUser._id);

    res.status(201).json({ message: 'User created successfully' });
  } catch (err) {
    console.error('Error registering user:', err);
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });

    if (user && await bcrypt.compare(password, user.password)) {
      generateToken(res, user._id);
      res.status(200).json({
        id: user._id,
        name: user.name,
        email: user.email,
        message: 'Login Successful'
      });
    } else {
      res.status(401).json({ message: 'Invalid email or password' });
    }
  } catch (err) {
    console.error('Error logging in:', err);
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
});

app.post('/logout', async (req, res) => {
  res.cookie("token", "", {
    httpOnly: true,
    expires: new Date(0)
  });
  res.status(200).json({ message: "Logged Out" });
});

app.post('/request-reset', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    user.reset_password_token = resetToken;
    user.reset_password_expiration = Date.now() + 3600000;

    await user.save();

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      to: user.email,
      from: 'nishanthsharma700053@gmail.com',
      subject: 'Password Reset',
      text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.
        Please click on the following link, or paste this into your browser to complete the process:
        http://${req.headers.host}/reset/${resetToken}
        If you did not request this, please ignore this email and your password will remain unchanged.`,
    };

    transporter.sendMail(mailOptions, (err) => {
      if (err) {
        console.error('Error sending email:', err);
        return res.status(500).json({ message: 'Error sending email', error: err.message });
      }
      res.status(200).json({ message: 'Recovery email sent' });
    });
  } catch (error) {
    console.error('Error processing reset request:', error);
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});

app.post('/reset/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    const user = await User.findOne({
      reset_password_token: token,
      reset_password_expiration: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ message: 'Password reset token is invalid or has expired' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;
    user.reset_password_token = undefined;
    user.reset_password_expiration = undefined;

    await user.save();
    res.status(200).json({ message: 'Password has been updated' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});

// to send the photos to the frontend from the server

app.get('/events', async (req, res) => {
  try {
    const events = await Event.find();
    res.json(events);
  } catch (err) {
    console.error('Error fetching events:', err);
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
});


app.post('/events', async (req, res) => {
  const { place, eventname, participationNumber, duration, address, image, startTime, endTime } = req.body;

  if (!place || !participationNumber || !duration || !address || !startTime || !endTime || !eventname) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  try {
    const newEvent = new Event({
      place,
      eventname,
      participationNumber,
      duration,
      address,
      image : image || '',
      startTime,
      endTime,
      attendees: []
    });
    await newEvent.save();
    res.status(201).json({ message: 'Event created successfully', event: newEvent });
  } catch (err) {
    console.error('Error creating event:', err);
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
});
app.post('/register/:eventId', async (req, res) => {
  const { eventId } = req.params;
  const { name, mobile, seats } = req.body;
  if (seats <= 0) {
    return res.status(400).json({ message: 'Seats must be a positive number' });
  }
  try {
    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: 'Event not found' });
    }
    const totalSeatsTaken = event.attendees.reduce((acc, attendee) => acc + attendee.seats, 0);
    const remainingSeats = event.participationNumber - totalSeatsTaken;
    if (remainingSeats < seats) {
      return res.status(400).json({ message: `Only ${remainingSeats} seats remaining` });
    }
    event.attendees.push({ name, mobile, seats });
    event.seatsTaken = totalSeatsTaken + seats; 
    await event.save();
    res.status(200).json({ message: 'Registration successful', event });
  } catch (error) {
    console.error('Error registering for event:', error);
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});
app.delete('/events/:eventId', async(req, res) => {
  const { eventId } = req.params;
  try{
    const event = await Event.findByIdAndDelete(eventId);
    if(!event){
      return res.status(404).json({message: 'Event Not found' });
    }
    res.status(200).json({message: 'Event Deleted Successfully'});
  }
  catch (error) {
    console.error('Error deleting event:', error);
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});



