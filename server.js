const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt'); // To hash passwords
const app = express();
const port = 5000; // Choose any port number you like

// Middleware
app.use(cors());
app.use(express.json()); // Parse JSON bodies

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/registrationDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log('Connected to MongoDB');
}).catch((error) => {
  console.log('Error connecting to MongoDB:', error);
});

// Define a Mongoose Schema with additional fields
const userSchema = new mongoose.Schema({
  fullName: {
    type: String,
    required: true,
  },
  username: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  phone: {
    type: String,
    required: true,
  },
  address: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
});

// Define a Mongoose Model
const User = mongoose.model('User', userSchema);

// Register a new user with additional fields
app.post('/register', async (req, res) => {
  const { fullName, username, email, phone, address, password } = req.body;

  try {
    // Check if the email is already registered
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already registered' });
    }

    // Hash the password before saving it to the database
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      fullName,
      username,
      email,
      phone,
      address,
      password: hashedPassword,
    });
    await newUser.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(400).json({ message: 'Error registering user', error });
  }
});

// Login a user
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password. Please register first.' });
    }

    // Check if password matches
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid email or password. Please register first.' });
    }

    res.status(200).json({ message: 'Login successful', user });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
});

// Contact schema for handling messages
const contactSchema = new mongoose.Schema({
  name: String,
  email: String,
  message: String,
});

const Contact = mongoose.model('Contact', contactSchema);

// Route to handle form submission
app.post('/contact', async (req, res) => {
  try {
    const newContact = new Contact(req.body);
    await newContact.save();
    res.status(201).json({ message: 'Message sent successfully!' });
  } catch (error) {
    res.status(500).json({ message: 'Error saving message' });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
