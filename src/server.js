require('dotenv').config({ path: require('find-config')('.env') });
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const authRouter = require("./routes/auth");

const app = express();

app.use(cors());
app.use(bodyParser.json());


const PORT = 5000;

// set setup endpoints in App
app.use("/api", authRouter);

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
