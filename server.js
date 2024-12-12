// Required Dependencies
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Database Connection
mongoose.connect('mongodb+srv://japanese_vocabulary:japanese_vocabulary@cluster0.gqju11e.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('Database connected successfully'))
  .catch(err => console.error('Database connection error:', err));

// Models
const UserSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String,
    role: { type: String, enum: ['Admin', 'User'], default: 'User' },
    profilePicture: String
});

const LessonSchema = new mongoose.Schema({
    name: String,
    number: Number,
    vocabularies: [{
        word: String,
        pronunciation: String,
        meaning: String,
        whenToUse: String
    }]
});

const User = mongoose.model('User', UserSchema);
const Lesson = mongoose.model('Lesson', LessonSchema);

// Authentication Middleware
const authenticate = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: 'Access denied' });
    try {
        const verified = jwt.verify(token, 'secret_key');
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).json({ error: 'Invalid token' });
    }
};

const authorize = (roles) => (req, res, next) => {
    if (!roles.includes(req.user.role)) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    next();
};

// Routes

// Registration
app.post('/register', async (req, res) => {
    try {
        const { name, email, password, profilePicture } = req.body;
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newUser = new User({ name, email, password: hashedPassword, profilePicture });
        await newUser.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Login
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: 'User not found' });
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) return res.status(400).json({ error: 'Invalid credentials' });
        const token = jwt.sign({ id: user._id, role: user.role }, 'secret_key', { expiresIn: '1d' });
        res.status(200).json({ token, role: user.role });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});


// Run Server
const PORT = 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
