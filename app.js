const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

app.use(express.json());

const User = require('./models/User');

app.get('/user/:id', checkToken, async (req, res) => {
    const id = req.params.id;

    const user = await User.findById(id, '-password');

    if (!user) {
        res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json({ user });
});

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access denied' });
    }

    try {
        const secret = process.env.SECRET;

        jwt.verify(token, secret);

        next();
    } catch (error) {
        res.status(500).json({ message: 'Invalid token' });
    }
}

app.post('/auth/register', async (req, res) => {
    const { name, email, password, confirmPassword } = req.body;

    if (!name) {
        return res.status(422).json({ message: 'Name is required' });
    }

    if (!email) {
        return res.status(422).json({ message: 'Email is required' });
    }

    if (!password) {
        return res.status(422).json({ message: 'Password is required' });
    }

    if (password != confirmPassword) {
        return res.status(422).json({ message: "Passwords aren't the same" });
    }

    const userExists = await User.findOne({ email: email });

    if (userExists) {
        return res.status(422).json({ message: 'Please, use another email' });
    }

    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    const user = new User({
        name,
        email,
        password: passwordHash,
    });

    try {
        await user.save();

        res.status(201).json({ message: 'User created' });
    } catch (error) {
        res.status(500).json({ message: 'Error' });
    }
});

app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email) {
        return res.status(422).json({ message: 'Email is required' });
    }

    if (!password) {
        return res.status(422).json({ message: 'Password is required' });
    }

    const user = await User.findOne({ email: email });

    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }

    const checkPassword = await bcrypt.compare(password, user.password);

    if (!checkPassword) {
        return res.status(422).json({ message: 'Invalid password' });
    }

    try {
        const secret = process.env.SECRET;

        const token = jwt.sign(
            {
                id: user._id,
            },
            secret
        );

        res.status(200).json({ message: 'User logged', token });
    } catch (error) {
        res.status(500).json({ message: 'Error' });
    }
});

const user = process.env.DB_USER;
const password = process.env.DB_PASSWORD;

mongoose
    .connect(
        `mongodb+srv://${user}:${password}@cluster0.tqqkrim.mongodb.net/?retryWrites=true&w=majority`
    )
    .then(() => {
        app.listen(3000, () => console.log('Server online'));
    })
    .catch((error) => console.log(error));
