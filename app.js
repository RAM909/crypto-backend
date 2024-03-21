const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const cors = require("cors");
const dotenv = require("dotenv");
const crypto = require("crypto");
const bcrypt = require('bcrypt');
const jwt = require("jsonwebtoken"); 

dotenv.config();
const PORT = process.env.PORT || 5000;

const app = express();
app.use(bodyParser.json());
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));

mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("Connected to MongoDB"))
    .catch(err => console.error("MongoDB connection error:", err));

const dataSchema = new mongoose.Schema({
    Id: String,
    MQ2: String,
    MQ5: String,
    MQ6: String,
    MQ7: String
});

const userSchema = new mongoose.Schema({
    userName: String,
    email: String,
    password: String
});

const DataModel = mongoose.model("Data", dataSchema);
const UserModel = mongoose.model("User", userSchema);



function encrypt(text, secretKey) {
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(secretKey, 'hex'), Buffer.alloc(16));
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return encrypted.toString('hex');
}

function decrypt(encryptedText, secretKey) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(secretKey, 'hex'), Buffer.alloc(16));
    let decrypted = decipher.update(Buffer.from(encryptedText, 'hex'));
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

app.post("/register", async (req, res) => {
    try {
        const { userName, email, password } = req.body;
        if (!userName || !email || !password) {
            return res.status(400).send({ message: "Please fill in all fields", success: false });
        }
        const userExists = await UserModel.findOne({ email });
        if (userExists) {
            return res.status(400).send({ message: "User already exists", success: false });
        }
        const hashedPassword = await bcrypt.hash(password, 12);

        const user = await UserModel.create({
            userName,
            email,
            password: hashedPassword,
        });

        return res.status(201).send({ message: "User created successfully", user, success: true });
    } catch (error) {
        console.log(error);
        return res.status(500).send({ message: error.message, success: false });
    }
});

app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log(email, password);
        if (!email || !password) {
            return res.status(400).send({ message: "Please fill in all fields", success: false });
        }
        const user = await UserModel.findOne({ email });
        if (!user) {
            return res.status(400).send({ message: "User does not exist", success: false });
        }
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(400).send({ message: "Invalid credentials", success: false });
        }
        user.password = undefined;
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
            expiresIn: "30d",
          });

        return res.status(200).send({ message: "User logged in successfully", user,token, success: true });
    } catch (error) {
        console.log(error);
        return res.status(500).send({ message: error.message, success: false });
    }
});

app.post("/add", async (req, res) => {
    const { Id, MQ2, MQ5, MQ6, MQ7 } = req.query;
    

    // Encrypt data before insertion
    const hashedmq2 = encrypt(MQ2, process.env.SECRET_KEY);
    const hashedmq5 = encrypt(MQ5, process.env.SECRET_KEY);
    const hashedmq6 = encrypt(MQ6, process.env.SECRET_KEY);
    const hashedmq7 = encrypt(MQ7, process.env.SECRET_KEY);

    try {
            const result = await DataModel.create({
                Id: Id,
                MQ2: hashedmq2,
                MQ5: hashedmq5,
                MQ6: hashedmq6,
                MQ7: hashedmq7
            });
            console.log(result);
            res.json("ADDED");
        
    } catch (e) {
        console.error(e);
        res.json("fail");
    }
});

app.get("/data", async (req, res) => {
    try {
        console.log(process.env.SECRET_KEY);

        const data = await DataModel.find();
        const decryptedData = data.map(item => ({
            Id: item.Id,
            MQ2: decrypt(item.MQ2, process.env.SECRET_KEY),
            MQ5: decrypt(item.MQ5, process.env.SECRET_KEY),
            MQ6: decrypt(item.MQ6, process.env.SECRET_KEY),
            MQ7: decrypt(item.MQ7, process.env.SECRET_KEY)
        }));
        res.json(decryptedData);
        console.log(decryptedData);
    } catch (err) {
        console.log(err);
        res.status(500).json("Error fetching data");
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}.`);
});
