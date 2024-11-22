const mongoose = require('mongoose');

// MongoDB URI with the correct format
const db = 'mongodb+srv://vishwas:vishwas@cluster0.eei0e.mongodb.net/myDatabase?retryWrites=true&w=majority';

const ConnectDB = async () => {
    try {
        // Connect to MongoDB without deprecated options
        await mongoose.connect(db);
        console.log('Connected to MongoDB successfully!');
    } catch (err) {
        console.error('MongoDB connection error:', err.message);
        process.exit(1);
    }
};

module.exports = ConnectDB;
