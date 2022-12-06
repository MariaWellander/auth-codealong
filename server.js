import express from 'express'
import bodyParser from 'body-parser'
import cors from 'cors'
// Using 3 different libraries
import mongoose from 'mongoose'
import crypto from 'crypto'
import bcrypt from 'bcrypt-nodejs'


// connected to our database
const mongoUrl = process.env.MONGO_URL || "mongodb://localhost/auth"
mongoose.connect(mongoUrl, { useNewUrlParser: true, useUnifiedTopology: true})
mongoose.Promise = Promise

// created a user model with some validation rules (unique & required) and a default access token (default) using the crypto library
const User = mongoose.model('User', {
  name: {
    type: String,
    unique: true
  },
  email:{
    type: String,
    unique: true
  },
  password:{
    type: String,
    required: true
  },
  accessToken:{
    type: String,
    default: () => crypto.randomBytes(128).toString('hex')
  }
});

// created a middleware function which looks up the user based on the accessToken stored in the header, which we can test via Postman. Calling the next() function which allows the protected endpoint to continue execution.
const authenticateUser = async (req, res, next) => {
  const user = await User.findOne({accessToken: req.header('Authorization')});
  if (user) {
    req.user = user;
    next();
  } else {
    res.status(401).json({loggedOut: true});
  }
}

// Defines the port the app will run on. Defaults to 8080, but can be 
// overridden when starting the server. For example:
//
//   PORT=9000 npm start
const port = process.env.PORT || 8080
const app = express()

// Add middlewares to enable cors and json body parsing
app.use(cors())
app.use(bodyParser.json())

// Start defining your routes here
app.get('/', (req, res) => {
  res.send('Hello world')
})

// created a registration endpoint where we can assign a name, email and password to our user in the database. (Remember not to store passwords in plain text or clear text!)
app.post('/users', async (req, res) => {
  try {
    const {name, email, password} = req.body;
    // DO NOT STORE PLAINTEXT PASSWORDS
    const user = new User({name, email, password: bcrypt.hashSync(password)});
    user.save();
    res.status(201).json({id: user._id, accessToken: user.accessToken});
  } catch (err) {
    res.status(400).json({message: 'Could not create user', errors: err.errors});
  }
});

// created a secret endpoint which could do anything but right now just returns a message. But this is the endpoint which is protected by our authenticateUser, so the user needs to be authenticated before being able to access it.
app.get('/secrets', authenticateUser);
app.get('/secrets', (req, res) =>{
  res.json({secret: 'This is a super secret message.'});
});

// created a login endpoint which is called sessions. Which does essentially the same as the registration endpoint except it does not creates the user it finds one. 
app.post('/sessions', async (req, res) => {
  const user = await User.findOne({email: req.body.email});
  if (user && bcrypt.compareSync(req.body.password , user.password)) {
    res.json({userId: user._id, accessToken: user.accessToken});
  } else {
    res.json({notFound: true});
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`)
})