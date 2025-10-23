import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// --- Environment variables ---
const AES_KEY = process.env.AES_KEY;
const OCR_API_KEY = process.env.OCR_API_KEY;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

if (!AES_KEY || AES_KEY.length !== 16) {
  throw new Error("AES_KEY must be exactly 16 characters long!");
}

// --- AES Encryption / Decryption ---
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

// --- SHA3-512 Hash ---
function sha3(data) {
  return crypto.createHash("sha3-512").update(data).digest("hex");
}

// --- KV Storage Functions ---
async function loadUsers() {
  const data = await USERS_KV.get("all");
  return data ? JSON.parse(data) : [];
}

async function saveUsers(users) {
  await USERS_KV.put("all", JSON.stringify(users));
}

async function loadHistory() {
  const data = await HISTORY_KV.get("all");
  return data ? JSON.parse(data) : [];
}

async function saveHistory(history) {
  await HISTORY_KV.put("all", JSON.stringify(history));
}

// --- REGISTER ---
app.post("/register", async (req, res) => {
  const { fullName, email, password, dob, userClass } = req.body;
  if (!fullName || !email || !password || !dob || !userClass)
    return res.json({ success: false, message: "Missing fields" });

  const users = await loadUsers();
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
  await saveUsers(users);
  res.json({ success: true, userId });
});

// --- LOGIN ---
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.json({ success: false, message: "Missing fields" });

  const users = await loadUsers();
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

// --- UPDATE USER CLASS ---
app.post("/updateUserClass", async (req, res) => {
  const { userId, userClass } = req.body;
  if (!userId || !Array.isArray(userClass))
    return res.json({ success: false, message: "Missing fields" });

  const users = await loadUsers();
  const idx = users.findIndex(u => u.userId === userId);
  if (idx === -1) return res.json({ success: false, message: "User not found" });

  users[idx].userClass = userClass.map(c => encrypt(c));
  await saveUsers(users);
  res.json({ success: true });
});

// --- UPDATE EXAM DATE ---
app.post("/updateExamDate", async (req, res) => {
  const { userId, examDate } = req.body;
  if (!userId) return res.json({ success: false, message: "User ID required" });

  const users = await loadUsers();
  const idx = users.findIndex(u => u.userId === userId);
  if (idx === -1) return res.json({ success: false, message: "User not found" });

  users[idx].examDate = examDate ? encrypt(examDate) : null;
  await saveUsers(users);
  res.json({ success: true });
});

// --- CALCULATE AGE ---
function calculateAge(dob) {
  if (!dob) return null;
  const birthDate = new Date(dob);
  const today = new Date();
  let age = today.getFullYear() - birthDate.getFullYear();
  const monthDiff = today.getMonth() - birthDate.getMonth();
  if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) age--;
  return age;
}

// --- OCR ---
app.post("/ocr", async (req, res) => {
  try {
    const formData = await req.formData();
    const file = formData.get("file");
    const userId = formData.get("userId");

    if (!file) return res.json({ extracted_text: "❌ No file uploaded" });

    const arrayBuffer = await file.arrayBuffer();
    const base64Image = Buffer.from(arrayBuffer).toString("base64");

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
                { text: "Extract all text from this image as accurately as possible:" },
                { inline_data: { mime_type: "image/png", data: base64Image } }
              ]
            }
          ]
        })
      }
    );

    const result = await response.json();
    let text = "⚠️ No text detected";
    if (result?.candidates?.[0]?.content?.parts?.[0]?.text) {
      text = result.candidates[0].content.parts[0].text.trim();
    } else if (result?.error?.message) {
      text = "❌ API Error: " + result.error.message;
    }

    if (userId && text && text !== "⚠️ No text detected") {
      const history = await loadHistory();
      history.push({ userId, ocr: encrypt(text), input: "", response: "", timestamp: new Date().toISOString() });
      await saveHistory(history);
    }

    res.json({ extracted_text: text });
  } catch (e) {
    res.json({ extracted_text: "❌ OCR failed: " + e.message });
  }
});

// --- ANALYZE ---
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
      : "Time remaining: Not specified (assuming 3 months for study planning)";

    const prompt = `You are an experienced tutor for Bangladeshi students. Create a comprehensive daily study routine based on the student's class level and syllabus.

Student Class: ${userClass && userClass.length ? userClass.join(", ") : "Not specified"}
${timeInfo}
Syllabus/Text: ${text}

Please provide a detailed daily study plan that includes:
1. Morning study session (subjects to focus on including academic time 9am-2pm for weekdays sunday to thursday)
2. Afternoon study session 
3. Evening revision time
4. Break times and physical activities
5. Recommended sleep schedule
6. Weekly review schedule

Make the routine realistic and suitable for the student's class level in the Bangladeshi education system. Consider the time available for exam preparation and adjust the intensity accordingly.
make the routine chapter wise and easy to finishable with full preparation do not make the response too long`;

    const aiResponse = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${GEMINI_API_KEY}`,
      { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] }) }
    );

    const aiData = await aiResponse.json();
    const analysis = aiData?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || "⚠️ No analysis returned";

    if (userId && text && analysis) {
      const history = await loadHistory();
      history.push({ userId, ocr: "", input: encrypt(text), response: encrypt(analysis), timestamp: new Date().toISOString() });
      await saveHistory(history);
    }

    res.json({ success: true, analysis });
  } catch (err) {
    console.error(err);
    res.json({ success: false, analysis: "❌ AI analysis failed." });
  }
});

// --- CHAT AI ---
app.post("/chatai", async (req, res) => {
  try {
    const formData = await req.formData();
    const userId = formData.get("userId");
    const message = formData.get("message");
    const file = formData.get("file");

    if (!userId || (!message && !file)) return res.json({ success: false, reply: "⚠️ No input provided" });

    let base64Image = null;
    if (file) {
      const arrayBuffer = await file.arrayBuffer();
      base64Image = Buffer.from(arrayBuffer).toString("base64");
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
    res.json({ success: false, reply: "❌ Chat AI failed." });
  }
});

// --- HISTORY ---
app.get("/history", async (req, res) => {
  const { userId } = req.query;
  if (!userId) return res.json({ history: [] });

  const history = await loadHistory();
  const userHistory = history.filter(h => h.userId == userId).map(h => ({
    input: h.input ? decrypt(h.input) : "",
    ocr: h.ocr ? decrypt(h.ocr) : "",
    response: h.response ? decrypt(h.response) : "",
    timestamp: h.timestamp
  }));

  res.json({ history: userHistory });
});

app.delete("/history", async (req, res) => {
  const { userId, index } = req.body;
  if (!userId || index == null) return res.json({ success: false });

  const history = await loadHistory();
  const userIndices = history.map((h, i) => h.userId == userId ? i : -1).filter(i => i !== -1);
  if (index < 0 || index >= userIndices.length) return res.json({ success: false });

  const delIndex = userIndices[index];
  history.splice(delIndex, 1);
  await saveHistory(history);
  res.json({ success: true });
});

// --- Default Routes ---
app.get("/", (req, res) => {
  res.status(200).sendFile(path.join(__dirname, "public", "index.html"));
});

app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, "public", "404.html"));
});

// --- Export Express App for Cloudflare Workers ---
import { createServer } from "express-cloudflare";
export default createServer(app);
