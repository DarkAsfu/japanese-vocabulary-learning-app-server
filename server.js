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

const authenticate = (req, res, next) => {
    const token = req.header('Authorization');
    console.log('Token:', token); // Debug the token

    if (!token) return res.status(401).json({ error: 'Access denied' });

    try {
        const verified = jwt.verify(token.split(' ')[1], 'secret_key'); // Ensure 'Bearer ' is stripped
        console.log('Verified Token:', verified); // Debug the decoded token
        req.user = verified;
        next();
    } catch (err) {
        console.error('Token Verification Error:', err.message);
        res.status(400).json({ error: 'Invalid token' });
    }
};

const authorize = (roles) => (req, res, next) => {
    console.log("user:", req.user);
    console.log('User Role:', req.user.role); // Debug the user's role
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
        res.status(200).json({ token, role: user.role, name: user.name, email: user.email, image: user.profilePicture });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.post('/logout', authenticate, (req, res) => {
    try {
        // Invalidate token by setting it to null on the client side
        res.status(200).json({ message: 'Logged out successfully' });
    } catch (error) {
        res.status(400).json({ error: 'Logout failed' });
    }
});

// Get All Users (Admin Only)
app.get('/users', authenticate, authorize(['Admin']), async (req, res) => {
    try {
        const users = await User.find({}, '_id name email role profilePicture'); // Exclude sensitive data
        res.status(200).json(users);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Update User Role (Admin Only)
app.patch('/users/:id/role', authenticate, authorize(['Admin']), async (req, res) => {
    try {
        const { id } = req.params;
        const { role } = req.body;

        // Validate the role
        if (!['Admin', 'User'].includes(role)) {
            return res.status(400).json({ error: 'Invalid role specified' });
        }

        // Update the role
        const user = await User.findByIdAndUpdate(id, { role }, { new: true });
        if (!user) return res.status(404).json({ error: 'User not found' });

        // Issue a new token for the user whose role was updated
        const newToken = jwt.sign(
            { id: user._id, role: user.role },
            'secret_key',
            { expiresIn: '1d' }
        );

        res.status(200).json({
            message: `User role updated to ${role}`,
            token: newToken, // Return the new token
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});


// Add Lesson (Admin Only)
app.post('/lessons', authenticate, authorize(['Admin']), async (req, res) => {
    try {
        const { name, number } = req.body;
        const newLesson = new Lesson({ name, number });
        await newLesson.save();
        res.status(201).json({ message: 'Lesson added successfully' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.get('/lessons', authenticate, async (req, res) => {
    try {
        const lessons = await Lesson.find({}, 'name number'); // Exclude sensitive data
        res.status(200).json(lessons);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});
app.get('/lessons/:lessonId', authenticate, async (req, res) => {
    try {
        const { lessonId } = req.params;
        const lesson = await Lesson.findById(lessonId, 'name number');
        if (!lesson) return res.status(404).json({ error: 'Lesson not found' });
        res.status(200).json(lesson);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});
// Update Lesson (Admin Only) 
app.patch('/lessons/:lessonId', authenticate, authorize(['Admin']), async (req, res) => {
    try {
        const { lessonId } = req.params;
        const { name, number } = req.body;
        const updatedLesson = await Lesson.findByIdAndUpdate(lessonId, { name, number }, { new: true });
        if (!updatedLesson) return res.status(404).json({ error: 'Lesson not found' });
        res.status(200).json({ message: 'Lesson updated successfully', updatedLesson });
    }
    catch (error) {
        res.status(400).json({ error: error.message });
    }
});
// Delete Lesson (Admin Only) 
app.delete('/lessons/:lessonId', authenticate, authorize(['Admin']), async (req, res) => {
    try {
        const { lessonId } = req.params;
        const deletedLesson = await Lesson.findByIdAndDelete(lessonId);
        if (!deletedLesson) return res.status(404).json({ error: 'Lesson not found' });
        res.status(200).json({ message: 'Lesson deleted successfully' });
    }
    catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Add Vocabulary to Lesson (Admin Only)
app.post('/lessons/:lessonId/vocabulary', authenticate, authorize(['Admin']), async (req, res) => {
    try {
        const { lessonId } = req.params;
        const { word, pronunciation, meaning, whenToUse } = req.body;
        const lesson = await Lesson.findById(lessonId);
        if (!lesson) return res.status(404).json({ error: 'Lesson not found' });
        lesson.vocabularies.push({ word, pronunciation, meaning, whenToUse });
        await lesson.save();
        res.status(201).json({ message: 'Vocabulary added successfully' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Run Server
const PORT = 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
