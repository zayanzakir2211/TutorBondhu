import express from "express";
import multer from "multer";
import fetch from "node-fetch";
import fs from "fs";
import crypto from "crypto";
import readline from "readline";
import path from "path";
import dotenv from "dotenv";
import { fileURLToPath } from "url";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const upload = multer({ dest: "uploads/" });

const OCR_API_KEY = process.env.OCR_API_KEY;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

// Local JSON storage for Node.js (will replace with KV if needed)
const USERS_FILE = path.join(__dirname, "users.json");
const HISTORY_FILE = path.join(__dirname, "history.json");

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ---------- AES Key Input ----------
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

rl.question("Enter your AES key (16 chars for AES-128): ", (AES_KEY) => {
  rl.close();

  if (!AES_KEY || AES_KEY.length !== 16) {
    console.error("AES key must be exactly 16 characters!");
    process.exit(1);
  }

  // ---------- AES Functions ----------
  function encrypt(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-128-cbc", AES_KEY, iv);
    let encrypted = cipher.update(text, "utf8", "hex");
    encrypted += cipher.final("hex");
    return iv.toString("hex") + ":" + encrypted;
  }

  function decrypt(data) {
    const [ivHex, encrypted] = data.split(":");
    const iv = Buffer.from(ivHex, "hex");
    const decipher = crypto.createDecipheriv("aes-128-cbc", AES_KEY, iv);
    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  }

  // ---------- SHA3-512 Hash ----------
  function sha3(data) {
    return crypto.createHash("sha3-512").update(data).digest("hex");
  }

  // ---------- Load / Save JSON ----------
  function loadJSON(file) {
    if (!fs.existsSync(file)) return [];
    try {
      const data = fs.readFileSync(file, "utf8").trim();
      return data ? JSON.parse(data) : [];
    } catch {
      return [];
    }
  }

  function saveJSON(file, data) {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
  }

  // ---------- USERS ----------
  function loadUsers() { return loadJSON(USERS_FILE); }
  function saveUsers(users) { saveJSON(USERS_FILE, users); }

  // ---------- HISTORY ----------
  function loadHistory() { return loadJSON(HISTORY_FILE); }
  function saveHistory(history) { saveJSON(HISTORY_FILE, history); }

  console.log("✅ AES key loaded successfully!");

  // ---------- REGISTER ----------
  app.post("/register", (req, res) => {
    const { fullName, email, password, dob, userClass } = req.body;
    if (!fullName || !email || !password || !dob || !userClass)
      return res.json({ success: false, message: "Missing fields" });

    let users = loadUsers();
    if (users.some(u => u.emailHash === sha3(email)))
      return res.json({ success: false, message: "Email already registered" });

    const userId = users.length > 0 ? Math.max(...users.map(u => u.userId)) + 1 : 1;

    const encUser = {
      userId,
      fullName: encrypt(fullName),
      emailHash: sha3(email),
      passwordHash: sha3(password),
      dob: encrypt(dob),
      userClass: userClass.map(c => encrypt(c)),
      examDate: null
    };

    users.push(encUser);
    saveUsers(users);
    res.json({ success: true, userId });
  });

  // ---------- LOGIN ----------
  app.post("/login", (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.json({ success: false, message: "Missing fields" });

    const users = loadUsers();
    const user = users.find(u => u.emailHash === sha3(email) && u.passwordHash === sha3(password));
    if (!user) return res.json({ success: false, message: "Invalid credentials" });

    const decryptedUser = {
      userId: user.userId,
      fullName: decrypt(user.fullName),
      email,
      dob: user.dob ? decrypt(user.dob) : null,
      userClass: user.userClass ? user.userClass.map(c => decrypt(c)) : [],
      examDate: user.examDate ? decrypt(user.examDate) : null
    };

    res.json({ success: true, user: decryptedUser });
  });

  // ---------- UPDATE USER CLASS ----------
  app.post("/updateUserClass", (req, res) => {
    const { userId, userClass } = req.body;
    if (!userId || !Array.isArray(userClass)) return res.json({ success: false });

    let users = loadUsers();
    const idx = users.findIndex(u => u.userId === userId);
    if (idx === -1) return res.json({ success: false, message: "User not found" });

    users[idx].userClass = userClass.map(c => encrypt(c));
    saveUsers(users);
    res.json({ success: true });
  });

  // ---------- UPDATE EXAM DATE ----------
  app.post("/updateExamDate", (req, res) => {
    const { userId, examDate } = req.body;
    if (!userId) return res.json({ success: false, message: "User ID required" });

    let users = loadUsers();
    const idx = users.findIndex(u => u.userId === userId);
    if (idx === -1) return res.json({ success: false, message: "User not found" });

    users[idx].examDate = examDate ? encrypt(examDate) : null;
    saveUsers(users);

    res.json({ success: true });
  });

  // ---------- CALCULATE AGE ----------
  function calculateAge(dob) {
    if (!dob) return null;
    const birthDate = new Date(dob);
    const today = new Date();
    let age = today.getFullYear() - birthDate.getFullYear();
    if (today.getMonth() < birthDate.getMonth() ||
        (today.getMonth() === birthDate.getMonth() && today.getDate() < birthDate.getDate())) {
      age--;
    }
    return age;
  }

  // ---------- OCR ----------
  app.post("/ocr", upload.single("file"), async (req, res) => {
    try {
      if (!req.file) return res.json({ extracted_text: "❌ No file uploaded" });
      const fileData = fs.readFileSync(req.file.path);
      const base64Image = fileData.toString("base64");

      const response = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${OCR_API_KEY}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            contents: [
              {
                role: "user",
                parts: [
                  { text: "Extract all text from this image:" },
                  { inline_data: { mime_type: "image/png", data: base64Image } }
                ]
              }
            ]
          })
        }
      );

      const result = await response.json();
      let text = result?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || "⚠️ No text detected";

      if (req.body.userId && text !== "⚠️ No text detected") {
        const history = loadHistory();
        history.push({
          userId: req.body.userId,
          ocr: encrypt(text),
          input: "",
          response: "",
          timestamp: new Date().toISOString()
        });
        saveHistory(history);
      }

      res.json({ extracted_text: text });
    } catch (e) {
      res.json({ extracted_text: "❌ OCR failed: " + e.message });
    } finally {
      if (req.file) fs.unlinkSync(req.file.path);
    }
  });

  // ---------- ANALYZE ----------
  app.post("/analyze", async (req, res) => {
    const { text, userClass, examDate, userId } = req.body;
    if (!text || !userId) return res.json({ success: false, analysis: "No text provided" });

    try {
      let monthsLeft = null;
      if (examDate) {
        const today = new Date();
        const exam = new Date(examDate);
        monthsLeft = (exam.getFullYear() - today.getFullYear()) * 12 + (exam.getMonth() - today.getMonth());
        if (exam.getDate() < today.getDate()) monthsLeft--;
      }

      const timeInfo = monthsLeft !== null && monthsLeft >= 0
        ? `Time remaining: ${monthsLeft} months`
        : "Time remaining: Not specified (assuming 3 months for planning)";

      const prompt = `You are a Bangladeshi student tutor.
Class: ${userClass && userClass.length ? userClass.join(", ") : "Not specified"}
${timeInfo}
Syllabus/Text: ${text}
Provide a detailed, realistic, chapter-wise daily study routine.`;

      const aiResponse = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${GEMINI_API_KEY}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] })
        }
      );

      const aiData = await aiResponse.json();
      const analysis = aiData?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || "⚠️ No analysis returned";

      if (userId) {
        const history = loadHistory();
        history.push({
          userId,
          ocr: "",
          input: encrypt(text),
          response: encrypt(analysis),
          timestamp: new Date().toISOString()
        });
        saveHistory(history);
      }

      res.json({ success: true, analysis });
    } catch (err) {
      console.error(err);
      res.json({ success: false, analysis: "❌ AI analysis failed" });
    }
  });

  // ---------- CHAT AI ----------
  app.post("/chatai", upload.single("file"), async (req, res) => {
    const { userId, message } = req.body;
    const file = req.file;
    if (!userId || (!message && !file)) return res.json({ success: false, reply: "⚠️ No input" });

    try {
      let base64Image = null;
      if (file) {
        base64Image = fs.readFileSync(file.path).toString("base64");
        fs.unlinkSync(file.path);
      }

      const contents = [{ role: "user", parts: [] }];
      if (message) contents[0].parts.push({ text: message });
      if (base64Image) contents[0].parts.push({ inline_data: { mime_type: "image/png", data: base64Image } });

      const aiResponse = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${GEMINI_API_KEY}`,
        { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ contents }) }
      );

      const aiData = await aiResponse.json();
      const reply = aiData?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || "⚠️ No reply from AI";

      res.json({ success: true, reply });
    } catch (err) {
      console.error(err);
      res.json({ success: false, reply: "❌ Chat AI failed" });
    }
  });

  // ---------- HISTORY ----------
  app.get("/history", (req, res) => {
    const { userId } = req.query;
    if (!userId) return res.json({ history: [] });

    const history = loadHistory().filter(h => h.userId == userId).map(h => ({
      input: h.input ? decrypt(h.input) : "",
      ocr: h.ocr ? decrypt(h.ocr) : "",
      response: h.response ? decrypt(h.response) : "",
      timestamp: h.timestamp
    }));

    res.json({ history });
  });

  app.delete("/history", (req, res) => {
    const { userId, index } = req.body;
    if (!userId || index == null) return res.json({ success: false });

    let history = loadHistory();
    const userIndices = history.map((h, i) => h.userId == userId ? i : -1).filter(i => i !== -1);
    if (index < 0 || index >= userIndices.length) return res.json({ success: false });

    history.splice(userIndices[index], 1);
    saveHistory(history);
    res.json({ success: true });
  });

  // ---------- DEFAULT ROUTES ----------
  app.get("/", (req, res) => {
    const indexPath = path.join(__dirname, "public", "index.html");
    fs.existsSync(indexPath) ? res.sendFile(indexPath) : res.status(404).send("Not Found");
  });

  app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, "public", "404.html"));
  });

  // ---------- START SERVER ----------
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
});
