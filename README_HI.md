# GitHub + Render + Turso Portal (Hindi Setup)

इस प्रोजेक्ट में मौजूदा `index.html` फ्रंटएंड, Node/Express API, Turso database, सुरक्षित admin login, signup/login, pending/active/blocked user status, Telegram signup alert और हर यूज़र के लिए अलग random-token link है। Admin URL: `/admin`.

## 1) पहले secrets सुरक्षित करें
आपने पहले चैट में Turso auth token जैसा secret साझा किया था। उसे Turso dashboard से revoke करके नया token बनाएं। Bot token कभी source code या GitHub में न डालें।

## 2) Turso तैयार करें
1. Turso में database बनाएँ या मौजूदा database इस्तेमाल करें।
2. Database URL का format `libsql://...turso.io` होगा।
3. Database के लिए नया auth token बनाएं और उसे केवल Render ENV में रखें।

## 3) GitHub पर upload
1. GitHub में नया **Private repository** बनाएँ।
2. इस ZIP को unzip करें और सभी files/folders repository की root में upload करें: `server.js`, `package.json`, `.gitignore`, `public/`, `README_HI.md`.
3. `.env.example` सिर्फ template है—इसमें असली secrets नहीं डालें। `.env` commit न करें।

## 4) Render Web Service
1. Render dashboard → **New +** → **Web Service** → GitHub repo connect करें।
2. Runtime/Language: **Node** (या dashboard में उपलब्ध Node.js runtime).
3. Root Directory खाली रखें (repo root).
4. Build Command: `npm install`
5. Start Command: `npm start`
6. Health Check Path: `/healthz`
7. Create Web Service करें। Official guide: https://render.com/docs/web-services

## 5) Render → Environment में ये variables डालें
हर variable का अपना Key और Value होगा:

- `TURSO_DATABASE_URL` = आपका पूरा Turso database URL
- `TURSO_AUTH_TOKEN` = नया Turso auth token (secret)
- `ADMIN_USERNAME` = अपना admin username, उदाहरण `portaladmin`
- `ADMIN_PASSWORD` = लंबा, unique admin password (कम से कम 16 characters रखें)
- `SESSION_SECRET` = कम से कम 32 random characters; उदाहरण के लिए password manager से random secret बनाएं
- `APP_BASE_URL` = Render service का पूरा URL, जैसे `https://your-service.onrender.com` (अंत में slash न लगाएँ)
- `TELEGRAM_BOT_TOKEN` = Telegram bot token; optional
- `TELEGRAM_CHAT_ID` = notification पाने वाला chat ID; optional
- `NODE_ENV` = `production`

Save and deploy करें। Render environment variables official guide: https://render.com/docs/configure-environment-variables

## 6) Test
- `https://YOUR-SERVICE.onrender.com/healthz` → `{"ok":true}`
- `https://YOUR-SERVICE.onrender.com/` → existing frontend
- `https://YOUR-SERVICE.onrender.com/admin` → admin login
- Signup पर user `pending` बनेगा; admin उसे Activate करे; फिर user login कर सकेगा।
- Admin में user चुनकर link label, destination URL और expiry days भरें। `0` का अर्थ no expiry है। Generated link को केवल उसी user को भेजें। Link एक bearer link है: जिसके पास link होगा, वह उसे खोल सकता है; इसलिए confidential links के लिए expiry रखें और जरूरत पड़ने पर revoke करें।

## 7) UptimeRobot (optional)
UptimeRobot में HTTP(s) monitor बनाकर `https://YOUR-SERVICE.onrender.com/healthz` दें। यह down-time detect करेगा; Render free service को हमेशा जागता रखने की guarantee नहीं देता।

## Important implementation notes
- User passwords bcrypt hash में सेव होते हैं; raw password database में नहीं जाता।
- Admin APIs session-protected हैं; user status server-side पर जाँचा जाता है।
- Telegram पर signup name/mobile/username notification जाता है; passwords/OTP नहीं भेजे जाते।
- `/u/<token>` link एक opaque bearer link है और destination पर redirect करता है। यह destination website के अपने login/access controls का विकल्प नहीं है।
- Render Free instance restart होने पर in-memory login sessions समाप्त हो सकते हैं; database data Turso में रहता है।
- Existing `index.html` design मूल uploaded frontend से है। इसके कुछ legacy UI controls/API assumptions अलग हो सकते हैं; backend/admin panel functional endpoints के साथ दिया गया है। Frontend को production में लगाने से पहले signup/login और post-login Screen 3 को test करें।
