// --- (1) IMPORTS ---
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// --- (2) CONFIGURATIONS & APP INITIALIZATION ---
const app = express();
// Note: PORT is not strictly needed for Vercel production,
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || "mongodb+srv://PetoraAdmin:Petora12301@cluster0.e1yal81.mongodb.net/";
const JWT_SECRET = process.env.JWT_SECRET || 'your-default-secret';

// --- (3) MIDDLEWARE ---
app.use(cors({
    origin: "*", // Allow all origins for now (or specify your frontend URL)
    credentials: true
}));
app.use(express.json());

// NOTE: Vercel does not support persistent file storage in 'uploads'. 
// Images uploaded here will disappear after a while. 
// For production, you should use Cloudinary or AWS S3.
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// --- (4) DATABASE CONNECTION (UPDATED FOR VERCEL) ---
// The video suggests using a middleware or cached connection pattern 
// so we don't create a new connection on every single request.

const connectDB = async () => {
    if (mongoose.connection.readyState === 0) {
        try {
            await mongoose.connect(MONGO_URI);
            console.log("MongoDB connected successfully.");
        } catch (err) {
            console.error("MongoDB connection error:", err);
        }
    }
};

// Add a middleware to ensure DB is connected before handling requests
app.use(async (req, res, next) => {
    await connectDB();
    next();
});

// --- (5) MONGOOSE MODELS ---
// (Keep your models exactly as they are)

// --- Shelter Model ---
const ShelterSchema = new mongoose.Schema({
  name: { type: String, required: true },
  location: { type: String, required: true },
  contactEmail: { type: String },
  contactPhone: { type: String },
}, { timestamps: true });
// ... (Check if model exists before compiling to avoid OverwriteModelError in serverless)
const Shelter = mongoose.models.Shelter || mongoose.model('Shelter', ShelterSchema);

// --- Shelter User Model ---
const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['shelter-admin', 'super-admin'], default: 'shelter-admin' },
    shelterRef: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'Shelter', 
        required: true 
    }
}, { timestamps: true });

UserSchema.pre('save', async function (next) {
    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 10);
    }
    next();
});
const User = mongoose.models.User || mongoose.model('User', UserSchema);

// --- Pet Model ---
const PetSchema = new mongoose.Schema({
  name: { type: String, required: true },
  species: { type: String, required: true },
  breed: { type: String },
  age: { type: Number },
  gender: { type: String, enum: ['Male', 'Female', 'Unknown'], default: 'Unknown' },
  size: { type: String, enum: ['Small', 'Medium', 'Large'], default: 'Medium' },
  description: { type: String, required: true },
  imageUrl: { type: String, required: true },
  status: { type: String, enum: ['Available', 'Pending', 'Adopted'], default: 'Available' },
  shelterId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Shelter',
    required: false
  }
}, { timestamps: true });
const Pet = mongoose.models.Pet || mongoose.model('Pet', PetSchema);

// --- Application Model ---
const ApplicationSchema = new mongoose.Schema({
  applicantName: { type: String, required: true },
  applicantEmail: { type: String, required: true },
  applicantPhone: { type: String, required: true },
  message: { type: String },
  status: { type: String, enum: ['Submitted', 'In-Review', 'Approved', 'Rejected'], default: 'Submitted' },
  petId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Pet',
    required: true
  }
}, { timestamps: true });
const Application = mongoose.models.Application || mongoose.model('Application', ApplicationSchema);


// --- (6.1) AUTH MIDDLEWARE ---
const protect = (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            token = req.headers.authorization.split(' ')[1];
            const decoded = jwt.verify(token, JWT_SECRET);
            req.user = decoded; 
            return next();
        } catch (error) {
            return res.status(401).json({ message: 'Not authorized, token failed' });
        }
    }
    return res.status(401).json({ message: 'Not authorized, no token' });
};

// --- (6.2) MULTER CONFIGURATION ---
// NOTE: For Vercel, you often need to use /tmp/ for temporary storage
const uploadDir = path.join('/tmp', 'uploads'); // Use /tmp for serverless environment
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
  console.log('path exists');
}
else{
  console.log('path does not exist');
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix);
  }
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image/')) {
    cb(null, true);
  } else {
    cb(new Error('Not an image! Please upload only images.'), false);
  }
};

const upload = multer({ storage: storage, fileFilter: fileFilter });


// --- (7) API ROUTES ---

app.get('/', (req, res) => {
    res.send("API is Running");
});

// A. Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const newUser = new User(req.body); 
        const savedUser = await newUser.save();
        res.status(201).json({ message: 'User registered successfully', userId: savedUser._id });
    } catch (error) {
        const errorMessage = error.code === 11000 ? 'Email already registered.' : error.message;
        res.status(400).json({ message: errorMessage });
    }
});

// B. Login
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ message: 'User not found' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

        const token = jwt.sign(
            { id: user._id, role: user.role, shelterId: user.shelterRef }, 
            JWT_SECRET, 
            { expiresIn: '1d' }
        );

        res.status(200).json({ token, role: user.role });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Shelter Routes
app.post('/api/shelters', async (req, res) => {
  try {
    const newShelter = new Shelter(req.body);
    const savedShelter = await newShelter.save();
    res.status(201).json(savedShelter);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.get('/api/shelters', async (req, res) => {
  try {
    const shelters = await Shelter.find();
    res.status(200).json(shelters);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Pet Routes
app.get('/api/pets', async (req, res) => {
  try {
    const filters = {};
    if (req.query.species) filters.species = req.query.species;
    if (req.query.size) filters.size = req.query.size;
    if (req.query.status) filters.status = req.query.status;
    
    const pets = await Pet.find(filters).populate('shelterId');
    res.status(200).json(pets);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/pets/:id', async (req, res) => {
  try {
    const pet = await Pet.findById(req.params.id).populate('shelterId');
    if (!pet) return res.status(404).json({ message: 'Pet not found' });
    res.status(200).json(pet);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// POST Pet
app.post('/api/pets', upload.single('image'), async (req, res) => {
  try {
    const { name, species, breed, age, gender, size, description, shelterId } = req.body;

    if (!req.file) {
      return res.status(400).json({ message: 'Image upload is required.' });
    }

    const imageUrl = req.file.path.replace(/\\/g, "/");

    const newPet = new Pet({
      name, species, breed, age, gender, size, description,
      shelterId: shelterId || null,
      imageUrl: imageUrl
    });

    const savedPet = await newPet.save();
    res.status(201).json(savedPet);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// PUT Pet
app.put('/api/pets/:id', async (req, res) => {
  try {
    const updatedPet = await Pet.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!updatedPet) return res.status(404).json({ message: 'Pet not found' });
    res.status(200).json(updatedPet);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// DELETE Pet
app.delete('/api/pets/:id', async (req, res) => {
  try {
    const deletedPet = await Pet.findByIdAndDelete(req.params.id);
    if (!deletedPet) return res.status(404).json({ message: 'Pet not found' });
    res.status(200).json({ message: 'Pet deleted successfully.' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Application Routes
app.post('/api/applications', async (req, res) => {
  try {
    const newApplication = new Application(req.body);
    const savedApplication = await newApplication.save();
    res.status(201).json(savedApplication);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.get('/api/applications', async (req, res) => {
 try {
  const applications = await Application.find().populate('petId');
    res.status(200).json(applications);
 } catch (error) {
    res.status(500).json({ message: error.message });
   }
});


// --- (8) START THE SERVER (UPDATED) ---
// We export the app for Vercel, but keep listen for local development
if (require.main === module) {
    app.listen(PORT, () => {
      console.log(`Server is running on http://localhost:${PORT}`);
    });
}

module.exports = app;