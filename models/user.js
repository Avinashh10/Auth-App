const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },     // NEW FIELD
  email: { type: String, required: true, unique: true },
  password: String
});

module.exports = mongoose.model('User', userSchema);

