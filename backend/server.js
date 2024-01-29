import express from "express";
import { MongoClient, ObjectId } from "mongodb";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();
const PORT = 4000;
const mongoURL = "mongodb://localhost:27017";
const dbName = "quirknotes";

// Connect to MongoDB
let db;

async function connectToMongo() {
	const client = new MongoClient(mongoURL);

	try {
		await client.connect();
		console.log("Connected to MongoDB");

		db = client.db(dbName);
	} catch (error) {
		console.error("Error connecting to MongoDB:", error);
	}
}

connectToMongo();

// Collections to manage
const COLLECTIONS = {
	notes: "notes",
	users: "users",
};

// Register a new user
app.post("/registerUser", express.json(), async (req, res) => {
	try {
		const { username, password } = req.body;

		// Basic body request check
		if (!username || !password) {
			return res.status(400).json({ error: "Username and password both needed to register." });
		}

		// Checking if username does not already exist in database
		const userCollection = db.collection(COLLECTIONS.users);
		const existingUser = await userCollection.findOne({ username });
		if (existingUser) {
			return res.status(400).json({ error: "Username already exists." });
		}

		// Creating hashed password (search up bcrypt online for more info)
		// and storing user info in database
		const hashedPassword = await bcrypt.hash(password, 10);
		await userCollection.insertOne({
			username,
			password: hashedPassword,
		});

		// Returning JSON Web Token (search JWT for more explanation)
		const token = jwt.sign({ username }, "secret-key", { expiresIn: "1h" });
		res.status(201).json({ response: "User registered successfully.", token });
	} catch (error) {
		res.status(500).json({ error: error.message });
	}
});

// Log in an existing user
app.post("/loginUser", express.json(), async (req, res) => {
	try {
		const { username, password } = req.body;

		// Basic body request check
		if (!username || !password) {
			return res.status(400).json({ error: "Username and password both needed to login." });
		}

		// Find username in database
		const userCollection = db.collection(COLLECTIONS.users);
		const user = await userCollection.findOne({ username });

		// Validate user against hashed password in database
		if (user && (await bcrypt.compare(password, user.password))) {
			const token = jwt.sign({ username }, "secret-key", { expiresIn: "1h" });

			// Send JSON Web Token to valid user
			res.json({ response: "User logged in succesfully.", token: token }); //Implicitly status 200
		} else {
			res.status(401).json({ error: "Authentication failed." });
		}
	} catch (error) {
		res.status(500).json({ error: error.message });
	}
});

// Post a note belonging to the user
app.post("/postNote", express.json(), async (req, res) => {
	try {
		// Basic body request check
		const { title, content } = req.body;
		if (!title || !content) {
			return res.status(400).json({ error: "Title and content are both required." });
		}

		// Verify the JWT from the request headers
		const token = req.headers.authorization.split(" ")[1];
		jwt.verify(token, "secret-key", async (err, decoded) => {
			if (err) {
				return res.status(401).send("Unauthorized.");
			}

			// Send note to database
			const collection = db.collection(COLLECTIONS.notes);
			const result = await collection.insertOne({
				title,
				content,
				username: decoded.username,
			});
			res.json({
				response: "Note added succesfully.",
				insertedId: result.insertedId,
			});
		});
	} catch (error) {
		res.status(500).json({ error: error.message });
	}
});

// Retrieve a note belonging to the user
app.get("/getNote/:noteId", express.json(), async (req, res) => {
	try {
		// Basic param checking
		const noteId = req.params.noteId;
		if (!ObjectId.isValid(noteId)) {
			return res.status(400).json({ error: "Invalid note ID." });
		}

		// Verify the JWT from the request headers
		const token = req.headers.authorization.split(" ")[1];
		jwt.verify(token, "secret-key", async (err, decoded) => {
			if (err) {
				return res.status(401).send("Unauthorized.");
			}

			// Find note with given ID
			const collection = db.collection(COLLECTIONS.notes);
			const data = await collection.findOne({
				username: decoded.username,
				_id: new ObjectId(noteId),
			});
			if (!data) {
				return res.status(404).json({ error: "Unable to find note with given ID." });
			}
			res.json({ response: data });
		});
	} catch (error) {
		res.status(500).json({ error: error.message });
	}
});

/*
Your task in this lab is to build upon this application by adding three additional endpoints to your server:

    a GET endpoint at /getAllNotes to retrieve all the existing notes for a specific user.
    a PATCH endpoint at /editNote/:noteId to edit an existing note given the id.
    a DELETE endpoint at /deleteNote/:noteId to delete an existing note given the id.

*/

// Retrieve all notes that belonging to the user
app.get("/getAllNotes", express.json(), async (req, res) => {
	try {
		// Verify the JWT from the request headers
		const token = req.headers.authorization.split(" ")[1];
		jwt.verify(token, "secret-key", async (err, decoded) => {
			if (err) {
				return res.status(401).send("Unauthorized.");
			}

			// Find note with given ID
			const collection = db.collection(COLLECTIONS.notes);
			const data = await collection
				.find({
					username: decoded.username,
				})
				.toArray();

			res.json({ response: data });
		});
	} catch (error) {
		res.status(500).json({ error: error.message });
	}
});

// Delete a note given the note ID
app.delete("/deleteNote/:noteId", express.json(), async (req, res) => {
	try {
		// Basic param checking
		const noteId = req.params.noteId;
		if (!ObjectId.isValid(noteId)) {
			return res.status(400).json({ error: "Invalid note ID." });
		}

		const token = req.headers.authorization.split(" ")[1];
		jwt.verify(token, "secret-key", async (err, decoded) => {
			if (err) {
				return res.status(401).send("Unauthorized.");
			}

			const collection = db.collection(COLLECTIONS.notes);
			const { deletedCount } = await collection.deleteOne({
				_id: new ObjectId(noteId),
				username: decoded.username,
			});
			if (deletedCount == undefined || deletedCount == 0) {
				return res.status(404).json({ response: `Note with ID ${noteId} belonging to the user not found` });
			}
			res.json({ response: `Document with ID ${noteId} properly deleted` });
		});
	} catch (error) {
		res.status(500).json({ error: error.message });
	}
});

// Modify a note given the note ID
app.patch("/editNote/:noteId", express.json(), async (req, res) => {
	try {
		// Basic param checking
		const noteId = req.params.noteId;
		if (!ObjectId.isValid(noteId)) {
			return res.status(400).json({ error: "Invalid note ID." });
		}

		// Basic body request check
		const { title, content } = req.body;
		if (!title && !content) {
			return res.status(400).json({ error: "At least title or content are required." });
		}
		const valids = {};
		if (title) valids["title"] = title;
		if (content) valids["content"] = content;

		const token = req.headers.authorization.split(" ")[1];
		jwt.verify(token, "secret-key", async (err, decoded) => {
			if (err) {
				return res.status(401).send("Unauthorized.");
			}

			const collection = db.collection(COLLECTIONS.notes);

			const data = await collection.updateOne(
				{
					_id: new ObjectId(noteId),
					username: decoded.username,
				},
				{
					$set: valids,
				}
			);
			console.log(data);
			if (!data || (data && data.matchedCount == 0)) {
				return res.status(404).json({ response: `Note with ID ${noteId} belonging to the user not found` });
			}
			res.json({ response: `Document with ID ${noteId} properly updated` });
		});
	} catch (error) {
		res.status(500).json({ error: error.message });
	}
});
// Open Port
app.listen(PORT, () => {
	console.log(`Server is running on http://localhost:${PORT}`);
});
